# Análise DINÂMICA: dispara requisições reais contra o app rodando e observa
# o comportamento (status, headers, cookies). Usa httpx assíncrono.
# Se o app estiver fora do ar, marca as checagens como SKIP (não falha o scan).
# Porte de lib/dynamic-analyzer.mjs.

import re
from dataclasses import dataclass
from typing import Optional

import httpx

from .models import STATUS, Finding, finding

TIMEOUT_S = 6.0


@dataclass
class ProbeResult:
    ok: bool
    status: Optional[int] = None
    headers: Optional[httpx.Headers] = None
    error: Optional[str] = None
    excerpt: str = ""


_SECRET_VALUE = re.compile(
    r'("(?:[\w-]*(?:password|passwd|senha|secret|token|api[_-]?key|authorization|cpf|ssn|card|cartao|private[_-]?key)[\w-]*)"\s*:\s*)"[^"]*"',
    re.I,
)


_CPF = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
_CARD = re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_EMAIL = re.compile(r"\b([A-Za-z0-9])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def _mask_pii(text: str) -> str:
    text = _CPF.sub("***.***.***-**", text)
    text = _CARD.sub("[CARTÃO]", text)
    text = _JWT.sub("[JWT]", text)
    return _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def _redact(text: str) -> str:
    """Evidência vai pra banco, Slack e GitHub — nunca carrega o segredo em si, só a prova de que ele estava exposto."""
    return _mask_pii(_SECRET_VALUE.sub(lambda m: m.group(1) + '"[REDACTED]"', text))


def _evidence(method: str, url: str, r: "ProbeResult") -> str:
    """Requisição feita + resposta recebida — o que o desenvolvedor precisa pra reproduzir."""
    if not r.ok:
        return ""
    body = _redact(" ".join((r.excerpt or "").split()))
    return f"{method} {url}\n→ HTTP {r.status}" + (f"\n{body}" if body else "")


async def _probe(client: httpx.AsyncClient, url: str, method: str = "GET", **kwargs) -> ProbeResult:
    try:
        res = await client.request(method, url, timeout=TIMEOUT_S, follow_redirects=False, **kwargs)
        return ProbeResult(ok=True, status=res.status_code, headers=res.headers, excerpt=res.text[:300])
    except Exception as err:  # noqa: BLE001 — probe de rede, qualquer falha vira SKIP
        return ProbeResult(ok=False, error=type(err).__name__)


def _is_protected(status: int, headers: httpx.Headers) -> bool:
    if status in (401, 403):
        return True
    if 300 <= status < 400:
        loc = headers.get("location", "")
        return bool(re.search(r"login|signin|auth", loc, re.I))
    return False


async def run_dynamic(target: dict) -> list[Finding]:
    base = (target.get("baseUrl") or "").rstrip("/")
    ep = target.get("endpoints") or {}
    out: list[Finding] = []

    async with httpx.AsyncClient() as client:
        health = await _probe(client, base + "/")
        if not health.ok:
            out.append(finding(
                id="D-ENV-00", category="AUTHORIZATION", status=STATUS.SKIP, severity="INFO", source="dynamic",
                title="App não está respondendo — análise dinâmica pulada",
                detail=f"Não consegui alcançar {base} ({health.error}). Suba o app e rode de novo para os testes ativos.",
                recommendation="Inicie o servidor do alvo para executar os probes dinâmicos.",
            ))
            return out

        # 1) Rotas protegidas devem negar acesso sem sessão.
        for i, p in enumerate(ep.get("protectedGet") or []):
            r = await _probe(client, base + p)
            if not r.ok:
                status, detail = STATUS.SKIP, f"Falha ao requisitar ({r.error})."
            elif _is_protected(r.status, r.headers):
                status, detail = STATUS.PASS, f"Retornou {r.status} sem sessão — acesso negado corretamente."
            elif r.status == 404:
                status, detail = STATUS.WARN, f"Retornou 404 — rota não encontrada no app que está rodando. Confirme que o alvo correto está no ar em {base}."
            else:
                status, detail = STATUS.FAIL, f"Retornou {r.status} sem sessão — dado potencialmente exposto!"
            out.append(finding(
                id=f"D-AUTHZ-0{i + 1}", category="AUTHORIZATION", severity="CRITICAL", source="dynamic",
                title=f"Acesso não autenticado negado em {p}",
                status=status, detail=detail,
                recommendation="Endpoints com dados do usuário devem retornar 401 sem sessão (OWASP API #1/#2).",
                evidence=_evidence("GET", base + p, r),
            ))

        # 2) Webhook deve rejeitar requisição sem assinatura válida.
        if ep.get("webhook"):
            r = await _probe(
                client, base + ep["webhook"], method="POST",
                headers={"content-type": "application/x-www-form-urlencoded"},
                content="From=whatsapp:+5511999999999&Body=ping",
            )
            if not r.ok:
                status, detail = STATUS.SKIP, f"Falha ao requisitar ({r.error})."
            elif r.status == 403:
                status, detail = STATUS.PASS, "Requisição forjada (sem x-twilio-signature) recebeu 403."
            elif r.status == 404:
                status, detail = STATUS.WARN, f"Retornou 404 — rota do webhook não encontrada no app rodando. Confirme o alvo em {base}."
            else:
                status, detail = STATUS.FAIL, f"Requisição sem assinatura recebeu {r.status} — deveria ser 403."
            out.append(finding(
                id="D-INTEG-01", category="INTEGRITY", severity="HIGH", source="dynamic",
                title="Webhook rejeita requisição sem assinatura",
                status=status, detail=detail,
                recommendation="Validar assinatura do provedor antes de processar qualquer webhook.",
                evidence=_evidence("POST", base + ep["webhook"], r),
            ))

        # 3) Cron interno deve exigir Bearer.
        if ep.get("cron"):
            r = await _probe(client, base + ep["cron"])
            if not r.ok:
                status, detail = STATUS.SKIP, f"Falha ao requisitar ({r.error})."
            elif r.status in (401, 403):
                status, detail = STATUS.PASS, f"Sem Bearer retornou {r.status} — negado."
            elif r.status == 404:
                status, detail = STATUS.WARN, f"Retornou 404 — rota do cron não encontrada no app rodando. Confirme o alvo em {base}."
            else:
                status, detail = STATUS.WARN, f"Sem Bearer retornou {r.status} — verifique se CRON_SECRET está configurado neste ambiente."
            out.append(finding(
                id="D-INTEG-02", category="INTEGRITY", severity="MEDIUM", source="dynamic",
                title="Endpoint de cron exige segredo (Bearer)",
                status=status, detail=detail,
                recommendation="Negar por padrão quando o segredo não estiver presente (fail-closed).",
                evidence=_evidence("GET", base + ep["cron"], r),
            ))

        # 4) Cabeçalhos de segurança na resposta.
        wanted = [
            ("strict-transport-security", "HSTS"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("content-security-policy", "Content-Security-Policy"),
            ("referrer-policy", "Referrer-Policy"),
        ]
        missing = [name for h, name in wanted if not health.headers.get(h)]
        out.append(finding(
            id="D-HEAD-01", category="HEADERS", severity="MEDIUM", source="dynamic",
            title="Cabeçalhos de segurança presentes na resposta",
            status=STATUS.PASS if not missing else STATUS.FAIL if len(missing) >= 4 else STATUS.WARN,
            detail=("Todos os cabeçalhos de segurança avaliados estão presentes." if not missing
                    else f"Ausentes: {', '.join(missing)}."),
            recommendation="Adicionar os cabeçalhos de segurança ausentes na resposta (via middleware/proxy do servidor).",
            evidence=f"{len(wanted) - len(missing)}/{len(wanted)} presentes",
        ))

        # 5) Divulgação de tecnologia/versão (X-Powered-By e Server).
        powered = health.headers.get("x-powered-by")
        server = health.headers.get("server")
        server_leaks = bool(server and re.search(r"werkzeug|flask|python|express|gunicorn|node|php|apache/|nginx/|\d+\.\d+", server, re.I))
        leaks = []
        if powered:
            leaks.append(f'X-Powered-By: "{powered}"')
        if server_leaks:
            leaks.append(f'Server: "{server}"')
        out.append(finding(
            id="D-INFO-01", category="HEADERS", severity="LOW", source="dynamic",
            title="Servidor não divulga tecnologia/versão",
            status=STATUS.WARN if leaks else STATUS.PASS,
            detail=f"Divulga tecnologia: {'; '.join(leaks)}." if leaks else "Não divulga X-Powered-By nem versão no header Server.",
            recommendation="Ocultar X-Powered-By e a versão no header Server para reduzir a superfície de reconhecimento (OWASP API8).",
        ))

        # 6) OAuth/OIDC exposto de forma saudável.
        if ep.get("authProviders"):
            r = await _probe(client, base + ep["authProviders"])
            out.append(finding(
                id="D-OIDC-01", category="OAUTH_OIDC", severity="INFO", source="dynamic",
                title="Provedores de autenticação disponíveis",
                status=STATUS.SKIP if not r.ok else STATUS.PASS if r.status == 200 else STATUS.WARN,
                detail=(f"Falha ao requisitar ({r.error})." if not r.ok
                        else "Endpoint de provedores respondeu 200 — OAuth/OIDC ativo." if r.status == 200
                        else f"Endpoint de provedores retornou {r.status}."),
                evidence=f"HTTP {r.status}" if r.ok else "",
            ))

        # 7) CORS mal configurado (wildcard + credenciais).
        cors_probe = await _probe(client, base + "/", headers={"Origin": "https://attacker-controlled.test"})
        if cors_probe.ok:
            allow_origin = cors_probe.headers.get("access-control-allow-origin", "")
            allow_creds = cors_probe.headers.get("access-control-allow-credentials", "").lower() == "true"
            wildcard_with_creds = allow_origin == "*" and allow_creds
            reflects_any_origin = allow_origin == "https://attacker-controlled.test" and allow_creds
            bad = wildcard_with_creds or reflects_any_origin
            out.append(finding(
                id="D-CORS-01", category="HEADERS", severity="HIGH", owasp="API8:2023", source="dynamic",
                title="CORS não permite qualquer origem com credenciais",
                status=STATUS.SKIP if not allow_origin else STATUS.FAIL if bad else STATUS.PASS,
                detail=(f"Access-Control-Allow-Origin: {allow_origin} + Allow-Credentials: true — qualquer site pode fazer requisições autenticadas em nome da vítima." if bad
                        else f"Access-Control-Allow-Origin: {allow_origin}, sem credenciais liberadas para origem arbitrária." if allow_origin
                        else "Nenhum cabeçalho CORS na resposta para uma origem não confiável (comportamento padrão do navegador já protege)."),
                recommendation="Nunca combinar Access-Control-Allow-Origin: * (ou refletir qualquer Origin) com Access-Control-Allow-Credentials: true; usar allowlist explícita de origens.",
                evidence=f"origin: {allow_origin or '-'} · credentials: {allow_creds}",
            ))
        else:
            out.append(finding(
                id="D-CORS-01", category="HEADERS", severity="HIGH", owasp="API8:2023", source="dynamic",
                title="CORS não permite qualquer origem com credenciais",
                status=STATUS.SKIP, detail=f"Falha ao requisitar ({cors_probe.error}).",
            ))

        # 8) Rate limiting — várias requisições rápidas devem eventualmente ser throttled.
        rate_target = (ep.get("protectedGet") or [None])[0] or "/"
        statuses = []
        for _ in range(20):
            r = await _probe(client, base + rate_target)
            if not r.ok:
                break
            statuses.append(r.status)
        throttled = any(s == 429 for s in statuses)
        out.append(finding(
            id="D-RATE-01", category="TRANSPORT", severity="MEDIUM", owasp="API4:2023", source="dynamic",
            title="Rate limiting — throttling sob rajada de requisições",
            status=STATUS.SKIP if len(statuses) < 20 else STATUS.PASS if throttled else STATUS.WARN,
            detail=(f"Só {len(statuses)}/20 requisições completaram — não deu pra concluir." if len(statuses) < 20
                    else "Recebeu 429 (Too Many Requests) durante a rajada — throttling ativo." if throttled
                    else "20 requisições seguidas em rajada, nenhuma bloqueada por rate limit."),
            recommendation="Aplicar rate limiting/quota por IP ou por token em endpoints custosos ou sensíveis (OWASP API4).",
            evidence=f"{len(statuses)} requisições · códigos: {sorted(set(statuses))}",
        ))

        # 9) Transporte.
        out.append(finding(
            id="D-TLS-01", category="TRANSPORT", severity="LOW", source="dynamic",
            title="Tráfego sobre HTTPS",
            status=STATUS.PASS if base.startswith("https://") else STATUS.WARN,
            detail=("Alvo acessado via HTTPS." if base.startswith("https://")
                    else "Alvo em HTTP (ambiente de desenvolvimento). Em produção, exigir HTTPS/HSTS."),
            recommendation="Forçar HTTPS e redirecionar HTTP→HTTPS em produção.",
        ))

    return out
