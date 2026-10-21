# Agendamento de scans por projeto (executado pelo scheduler em background).

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..db.models import ScheduleModel, TargetModel
from ..db.session import get_db

router = APIRouter(prefix="/api/targets/{target_id}/schedule", tags=["schedules"])
ALLOWED_HOURS = (1, 6, 12, 24, 168)


def _serialize(s: Optional[ScheduleModel]) -> dict:
    if not s:
        return {"enabled": False, "intervalHours": None, "nextRunAt": None, "lastRunAt": None, "lastStatus": None}
    return {
        "enabled": s.enabled, "intervalHours": s.interval_hours, "nextRunAt": s.next_run_at.isoformat(),
        "lastRunAt": s.last_run_at.isoformat() if s.last_run_at else None, "lastStatus": s.last_status,
    }


class ScheduleBody(BaseModel):
    intervalHours: int


@router.get("")
def get_schedule(target_id: str, db: Session = Depends(get_db)):
    return _serialize(db.query(ScheduleModel).filter(ScheduleModel.target_id == target_id).one_or_none())


@router.put("")
def set_schedule(target_id: str, body: ScheduleBody, db: Session = Depends(get_db), user=Depends(get_current_user)):
    if body.intervalHours not in ALLOWED_HOURS:
        raise HTTPException(400, f"Intervalo inválido — use um de: {', '.join(map(str, ALLOWED_HOURS))} hora(s).")
    if not db.query(TargetModel).filter(TargetModel.id == target_id).first():
        raise HTTPException(404, "Alvo não encontrado")
    s = db.query(ScheduleModel).filter(ScheduleModel.target_id == target_id).one_or_none()
    next_run = datetime.now(timezone.utc) + timedelta(hours=body.intervalHours)
    if s:
        s.interval_hours, s.enabled, s.next_run_at = body.intervalHours, True, next_run
    else:
        s = ScheduleModel(target_id=target_id, interval_hours=body.intervalHours, next_run_at=next_run, created_by=user.email)
        db.add(s)
    db.commit()
    db.refresh(s)
    return _serialize(s)


@router.delete("", status_code=204)
def delete_schedule(target_id: str, db: Session = Depends(get_db)):
    s = db.query(ScheduleModel).filter(ScheduleModel.target_id == target_id).one_or_none()
    if s:
        db.delete(s)
        db.commit()
