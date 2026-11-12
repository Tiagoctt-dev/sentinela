# Ciclo de vida da triagem de um achado ao longo das execuções.
#
#  - Um achado é identificado por (projeto, id da política, método+rota do ativo).
#  - Aceite de risco pode ter validade; ao vencer o achado volta a "open" (expire_risk_acceptances).
#  - Aceite de risco VIGENTE é herdado pelo mesmo achado no scan seguinte (inherit_triage), para a triagem
#    não se perder a cada execução. "Resolvido" NÃO é herdado: se o problema reaparece, precisa ser reavaliado.
#  - O histórico mostra quando o achado apareceu pela primeira vez, se reapareceu (regressão) e o estado em cada scan.

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..db.models import FindingModel, ScanRun

PROBLEM_STATES = ("vulnerable", "likely")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def asset_key(f: FindingModel) -> tuple[str, str]:
    a = f.asset or {}
    return (str(a.get("method") or ""), str(a.get("path") or ""))


def expire_risk_acceptances(db: Session) -> int:
    """Aceites de risco vencidos voltam a 'open', com a nota registrando o vencimento. Devolve quantos."""
    now = _now()
    rows = (
        db.query(FindingModel)
        .filter(FindingModel.resolution == "risk_accepted", FindingModel.resolution_expires_at.isnot(None))
        .all()
    )
    n = 0
    for f in rows:
        exp = _aware(f.resolution_expires_at)
        if exp and exp <= now:
            note = f.resolution_note or ""
            f.resolution = "open"
            f.resolution_note = f"[Aceite de risco expirou em {exp.strftime('%d/%m/%Y')}] {note}".strip()
            f.resolution_expires_at = None
            n += 1
    if n:
        db.commit()
    return n


def inherit_triage(db: Session, run: ScanRun, rows: list[FindingModel]) -> int:
    """Copia o aceite de risco vigente do scan anterior do mesmo projeto para os achados equivalentes."""
    prev = (
        db.query(ScanRun)
        .filter(ScanRun.target_id == run.target_id, ScanRun.id != run.id, ScanRun.created_at < run.created_at)
        .order_by(ScanRun.created_at.desc())
        .first()
    )
    if not prev:
        return 0
    accepted = {
        (f.finding_id, *asset_key(f)): f
        for f in db.query(FindingModel).filter(FindingModel.run_id == prev.id, FindingModel.resolution == "risk_accepted").all()
    }
    now, n = _now(), 0
    for r in rows:
        if r.state not in PROBLEM_STATES:
            continue
        old = accepted.get((r.finding_id, *asset_key(r)))
        if not old:
            continue
        exp = _aware(old.resolution_expires_at)
        if exp and exp <= now:
            continue
        r.resolution, r.resolution_expires_at, r.resolution_by = "risk_accepted", old.resolution_expires_at, old.resolution_by
        r.resolution_note = f"[Herdado do scan anterior] {old.resolution_note or ''}".strip()
        n += 1
    if n:
        db.commit()
    return n


def finding_history(db: Session, f: FindingModel, run: ScanRun, limit: int = 12) -> dict:
    """Estado do mesmo achado (mesma política e mesmo ativo) nas últimas execuções do projeto."""
    runs = (
        db.query(ScanRun)
        .filter(ScanRun.target_id == run.target_id, ScanRun.created_at <= run.created_at)
        .order_by(ScanRun.created_at.desc())
        .limit(limit)
        .all()
    )
    key = (f.finding_id, *asset_key(f))
    by_run: dict[str, FindingModel] = {}
    if runs:
        for row in db.query(FindingModel).filter(FindingModel.run_id.in_([r.id for r in runs]), FindingModel.finding_id == f.finding_id).all():
            if (row.finding_id, *asset_key(row)) == key:
                by_run[row.run_id] = row
    timeline = [
        {"scanId": r.id, "createdAt": r.created_at.isoformat(), "state": by_run[r.id].state if r.id in by_run else None}
        for r in reversed(runs)
    ]
    seen = [t for t in timeline if t["state"] in PROBLEM_STATES]
    states = [t["state"] for t in timeline if t["state"] is not None]
    # regressão: já esteve aprovado e voltou a ter problema
    regression = any(a == "passed" and b in PROBLEM_STATES for a, b in zip(states, states[1:]))
    return {
        "timeline": timeline,
        "firstSeenAt": seen[0]["createdAt"] if seen else None,
        "occurrences": len(seen),
        "regression": regression,
        "windowScans": len(timeline),
    }
