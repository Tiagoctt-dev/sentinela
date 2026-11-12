# Retenção de dados: o que guardar e por quanto tempo.
#
#   SENTINELA_AUDIT_RETENTION_DAYS  (padrão 365) — trilha de auditoria; 0 = nunca apagar
#   SENTINELA_SCAN_RETENTION_DAYS   (padrão 0)   — scans (e seus achados/evidências); 0 = nunca apagar
#   SENTINELA_LOGIN_FAILURE_MINUTES (fixo, 60)   — tentativas de login falhas
#
# Regra de segurança dos dados: o scan MAIS RECENTE de cada projeto nunca é apagado pela retenção
# (ele representa o estado atual e alimenta Achados, Rotas e Dashboard).

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .db.models import AuditLogModel, LoginFailureModel, ScanRun


def _days(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


def policy() -> dict:
    return {
        "auditDays": _days("SENTINELA_AUDIT_RETENTION_DAYS", 365),
        "scanDays": _days("SENTINELA_SCAN_RETENTION_DAYS", 0),
    }


def purge(db: Session, now: datetime | None = None) -> dict:
    """Aplica a política e devolve quanto foi removido. Idempotente."""
    from .api.common import latest_scan_per_target  # import tardio: evita ciclo

    now = now or datetime.now(timezone.utc)
    pol = policy()
    removed = {"audit": 0, "scans": 0, "loginFailures": 0}

    if pol["auditDays"]:
        removed["audit"] = db.query(AuditLogModel).filter(AuditLogModel.created_at < now - timedelta(days=pol["auditDays"])).delete(synchronize_session=False)

    removed["loginFailures"] = db.query(LoginFailureModel).filter(LoginFailureModel.created_at < now - timedelta(minutes=60)).delete(synchronize_session=False)

    if pol["scanDays"]:
        keep = {r.id for r in latest_scan_per_target(db)}
        old = db.query(ScanRun).filter(ScanRun.created_at < now - timedelta(days=pol["scanDays"])).all()
        for run in old:
            if run.id not in keep:
                db.delete(run)  # cascata remove os achados
                removed["scans"] += 1
    db.commit()
    return removed
