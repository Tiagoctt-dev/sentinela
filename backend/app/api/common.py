# Helpers compartilhados entre rotas (achados, stats) — nada aqui monta router.

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db.models import ScanRun


def latest_scan_per_target(db: Session) -> list[ScanRun]:
    """O scan mais recente de cada alvo — representa o estado atual (evita
    inflar contagens/achados com reruns antigos do mesmo alvo)."""
    sub = (
        db.query(ScanRun.target_id, func.max(ScanRun.created_at).label("max_created"))
        .group_by(ScanRun.target_id)
        .subquery()
    )
    return (
        db.query(ScanRun)
        .join(sub, (ScanRun.target_id == sub.c.target_id) & (ScanRun.created_at == sub.c.max_created))
        .all()
    )
