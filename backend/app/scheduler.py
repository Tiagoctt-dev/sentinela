# Agendador de scans: a cada minuto executa os agendamentos vencidos, usando
# exatamente o mesmo fluxo de um scan manual (inclusive integrações).

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from .db.models import ScheduleModel, TargetModel
from .db.session import SessionLocal

logger = logging.getLogger(__name__)
CHECK_EVERY_S = 60


async def _run_due() -> None:
    from .api.routes_scans import run_target_scan  # import tardio: evita ciclo

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = db.query(ScheduleModel).filter(ScheduleModel.enabled.is_(True), ScheduleModel.next_run_at <= now).all()
        for sch in due:
            target = db.query(TargetModel).filter(TargetModel.id == sch.target_id).one_or_none()
            # avança antes de rodar: uma execução lenta ou com erro não é repetida em loop
            sch.next_run_at = now + timedelta(hours=sch.interval_hours)
            sch.last_run_at = now
            db.commit()
            if not target:
                continue
            try:
                await run_target_scan(db, target, created_by="agendador", origin="agendado")
                sch.last_status = "ok"
            except Exception as err:  # noqa: BLE001 — um alvo com problema não derruba o agendador
                logger.warning("Scan agendado falhou (%s): %s", target.id, err)
                sch.last_status = f"falha: {str(err)[:200]}"
            db.commit()
    finally:
        db.close()


async def scheduler_loop() -> None:
    while True:
        try:
            await _run_due()
        except Exception:  # noqa: BLE001
            logger.exception("Erro no agendador")
        await asyncio.sleep(CHECK_EVERY_S)
