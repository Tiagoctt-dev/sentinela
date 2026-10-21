# Dispara as integrações cadastradas (webhook genérico, GitHub Issues, Slack)
# depois de um scan terminar. Best-effort: nunca deixa uma falha de integração
# derrubar a resposta do scan — só registra o resultado (status/erro) pra
# aparecer na tela de Integrações.

from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from ..db.models import FindingModel, GithubIntegrationModel, SlackIntegrationModel, WebhookModel

TIMEOUT_S = 6.0


def _now():
    return datetime.now(timezone.utc)


async def fire_scan_completed(db: Session, scan_payload: dict) -> None:
    webhooks = db.query(WebhookModel).filter(WebhookModel.enabled.is_(True)).all()
    if not webhooks:
        return

    body = {"event": "scan.completed", "scan": scan_payload}
    async with httpx.AsyncClient() as client:
        for wh in webhooks:
            try:
                res = await client.post(wh.url, json=body, timeout=TIMEOUT_S)
                wh.last_status = f"HTTP {res.status_code}" if res.is_success else f"erro HTTP {res.status_code}"
            except Exception as err:  # noqa: BLE001 — webhook de terceiro, nunca deixa derrubar o scan
                wh.last_status = f"falha: {err}"
            wh.last_triggered_at = _now()
    db.commit()


async def fire_scan_completed_slack(db: Session, scan_payload: dict) -> None:
    """Alerta no Slack quando o scan não sai conforme. Reusa a mesma URL de
    Incoming Webhook do Slack, só que com o payload {"text": ...} que o Slack
    espera em vez do JSON genérico do webhook acima."""
    if scan_payload.get("verdict") == "Conforme":
        return

    integrations = db.query(SlackIntegrationModel).filter(SlackIntegrationModel.enabled.is_(True)).all()
    if not integrations:
        return

    lines = [
        f":rotating_light: *Sentinela* — scan de *{scan_payload.get('targetName')}* voltou "
        f"*{scan_payload.get('verdict')}* (score {scan_payload.get('overall')}/100)."
    ]
    for f in (scan_payload.get("topFindings") or [])[:5]:
        first_line = (f.get("evidence") or "").splitlines()[0] if f.get("evidence") else ""
        where = f" — `{first_line}`" if first_line else ""
        lines.append(f"• *{f['severity']}* {f['title']}{where}")
    if scan_payload.get("scanUrl"):
        lines.append(f"<{scan_payload['scanUrl']}|Ver o scan completo>")
    text = "\n".join(lines)
    body = {"text": text}
    async with httpx.AsyncClient() as client:
        for s in integrations:
            try:
                res = await client.post(s.webhook_url, json=body, timeout=TIMEOUT_S)
                s.last_status = f"HTTP {res.status_code}" if res.is_success else f"erro HTTP {res.status_code}"
            except Exception as err:  # noqa: BLE001 — integração de terceiro, nunca deixa derrubar o scan
                s.last_status = f"falha: {err}"
            s.last_triggered_at = _now()
    db.commit()


async def fire_scan_completed_github(db: Session, scan_payload: dict, findings: list[FindingModel]) -> None:
    """Cria uma issue no GitHub pra cada achado crítico (severity=CRITICAL,
    status=FAIL) do scan."""
    integrations = db.query(GithubIntegrationModel).filter(GithubIntegrationModel.enabled.is_(True)).all()
    if not integrations:
        return

    critical = [f for f in findings if f.severity == "CRITICAL" and f.status == "FAIL"]
    if not critical:
        for g in integrations:
            g.last_status = "sem achados críticos neste scan"
            g.last_triggered_at = _now()
        db.commit()
        return

    async with httpx.AsyncClient() as client:
        for g in integrations:
            headers = {"Authorization": f"Bearer {g.token}", "Accept": "application/vnd.github+json"}
            created, failed = 0, 0
            for f in critical:
                title = f"[Sentinela] {f.title}"
                body_lines = [
                    f"**Alvo:** {scan_payload.get('targetName')}",
                    f"**Scan:** {scan_payload.get('scanUrl')}",
                    f"**Categoria:** {f.category}",
                    f"**Severidade:** {f.severity}",
                ]
                if f.owasp:
                    body_lines.append(f"**OWASP:** {f.owasp}")
                if f.detail:
                    body_lines.append(f"\n**Detalhe:**\n{f.detail}")
                if f.evidence:
                    body_lines.append(f"\n**Evidência:**\n```\n{f.evidence}\n```")
                if f.recommendation:
                    body_lines.append(f"\n**Recomendação:**\n{f.recommendation}")
                try:
                    res = await client.post(
                        f"https://api.github.com/repos/{g.repo}/issues",
                        headers=headers,
                        json={"title": title, "body": "\n".join(body_lines), "labels": ["sentinela", f.severity.lower()]},
                        timeout=TIMEOUT_S,
                    )
                    if res.is_success:
                        created += 1
                    else:
                        failed += 1
                except Exception:  # noqa: BLE001 — integração de terceiro, nunca deixa derrubar o scan
                    failed += 1
            if failed == 0:
                g.last_status = f"{created} issue(s) criada(s)"
            elif created == 0:
                g.last_status = f"falha ao criar {failed} issue(s)"
            else:
                g.last_status = f"{created} issue(s) criada(s), {failed} falharam"
            g.last_triggered_at = _now()
    db.commit()
