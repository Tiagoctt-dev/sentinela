# Agendador: a cada minuto executa os scans agendados vencidos (mesmo fluxo de um scan manual, inclusive
# integrações) e, uma vez por dia, aplica a política de retenção e expira aceites de risco vencidos.
#
# Vários processos/workers podem rodar o agendador ao mesmo tempo: cada agendamento é "reivindicado" com um
# UPDATE condicional — só quem altera a linha executa, então a mesma execução não é duplicada.

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from .db.models import ScheduleModel, TargetModel
from .db.session import SessionLocal

logger = logging.getLogger(__name__)
CHECK_EVERY_S = 60
MAINTENANCE_EVERY = timedelta(hours=24)
_last_maintenance: datetime | None = None


def claim(db, schedule: ScheduleModel, now: datetime) -> bool:
    """True se ESTE processo ganhou o direito de executar (o próximo horário já fica gravado)."""
    res = db.execute(
        update(ScheduleModel)
        .where(ScheduleModel.id == schedule.id, ScheduleModel.next_run_at == schedule.next_run_at, ScheduleModel.enabled.is_(True))
        .values(next_run_at=now + timedelta(hours=schedule.interval_hours), last_run_at=now)
    )
    db.commit()
    return res.rowcount == 1


async def _run_due() -> None:
    from .api.routes_scans import run_target_scan  # import tardio: evita ciclo

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = db.query(ScheduleModel).filter(ScheduleModel.enabled.is_(True), ScheduleModel.next_run_at <= now).all()
        for sch in due:
            if not claim(db, sch, now):
                continue  # outro processo pegou
            target = db.query(TargetModel).filter(TargetModel.id == sch.target_id).one_or_none()
            if not target:
                continue
            try:
                await run_target_scan(db, target, created_by="agendador", origin="agendado")
                status = "ok"
            except Exception as err:  # noqa: BLE001 — um alvo com problema não derruba o agendador
                detail = getattr(err, "detail", None) or str(err)
                logger.warning("Scan agendado falhou (%s): %s", target.id, detail)
                status = f"falha: {str(detail)[:200]}"
            db.query(ScheduleModel).filter(ScheduleModel.id == sch.id).update({"last_status": status})
            db.commit()
    finally:
        db.close()


def run_maintenance() -> dict:
    from .retention import purge
    from .domain.triage import expire_risk_acceptances

    db = SessionLocal()
    try:
        expired = expire_risk_acceptances(db)
        removed = purge(db)
        if expired or any(removed.values()):
            logger.info("Manutenção: %s aceites de risco expirados, removidos=%s", expired, removed)
        return {"expiredRiskAcceptances": expired, **removed}
    finally:
        db.close()


async def scheduler_loop() -> None:
    global _last_maintenance
    while True:
        try:
            await _run_due()
            now = datetime.now(timezone.utc)
            if _last_maintenance is None or now - _last_maintenance >= MAINTENANCE_EVERY:
                await asyncio.to_thread(run_maintenance)
                _last_maintenance = now
        except Exception:  # noqa: BLE001
            logger.exception("Erro no agendador")
        await asyncio.sleep(CHECK_EVERY_S)
