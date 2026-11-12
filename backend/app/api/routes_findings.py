# "Achados" globais — visão consolidada dos findings do scan mais recente de
# cada alvo, com workflow de triagem (aberto/resolvido/risco aceito, com validade opcional).

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..db.models import FindingModel, ScanRun
from ..db.session import get_db
from ..domain.policy_catalog import owasp_for_check
from ..domain.triage import expire_risk_acceptances, finding_history
from .common import latest_scan_per_target

router = APIRouter(prefix="/api/findings", tags=["findings"])

RESOLUTIONS = {"open", "resolved", "risk_accepted"}
MAX_PAGE = 5000


def _to_dict(f: FindingModel, run: ScanRun) -> dict:
    return {
        "rowId": f.id, "id": f.finding_id, "scanId": run.id, "targetId": run.target_id,
        "targetName": run.target_name, "category": f.category, "title": f.title, "status": f.status,
        "severity": f.severity, "detail": f.detail, "recommendation": f.recommendation,
        "evidence": f.evidence, "source": f.source, "owasp": f.owasp or owasp_for_check(f.finding_id), "data": f.data, "aiRec": f.ai_rec,
        "state": f.state, "confidence": f.confidence, "asset": f.asset, "meta": f.meta,
        "resolution": f.resolution, "resolutionNote": f.resolution_note, "createdAt": run.created_at.isoformat(),
        "resolutionExpiresAt": f.resolution_expires_at.isoformat() if f.resolution_expires_at else None,
        "resolutionBy": f.resolution_by,
    }


def _latest_runs(db: Session, target_id: Optional[str]) -> dict[str, ScanRun]:
    latest = latest_scan_per_target(db)
    if target_id:
        latest = [r for r in latest if r.target_id == target_id]
    return {r.id: r for r in latest}


@router.get("/count")
def count_findings(
    db: Session = Depends(get_db),
    resolution: Optional[str] = "open",
    targetId: Optional[str] = None,
):
    """Contador leve (vulnerabilidades confirmadas e prováveis no último scan de cada projeto) — usado no menu."""
    expire_risk_acceptances(db)
    runs = _latest_runs(db, targetId)
    if not runs:
        return {"count": 0}
    q = db.query(FindingModel.id).filter(FindingModel.run_id.in_(runs.keys()), FindingModel.state.in_(("vulnerable", "likely")))
    if resolution:
        q = q.filter(FindingModel.resolution == resolution)
    return {"count": q.count()}


@router.get("")
def list_findings(
    response: Response,
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    state: Optional[str] = None,
    confidence: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    resolution: Optional[str] = None,
    targetId: Optional[str] = None,
    q: Optional[str] = None,
    onlyActionable: bool = True,
    limit: int = Query(1000, ge=1, le=MAX_PAGE),
    offset: int = Query(0, ge=0),
):
    expire_risk_acceptances(db)
    runs = _latest_runs(db, targetId)
    if not runs:
        response.headers["X-Total-Count"] = "0"
        return []
    query = db.query(FindingModel).filter(FindingModel.run_id.in_(runs.keys()))
    if onlyActionable:
        query = query.filter(FindingModel.state.in_(("vulnerable", "likely")))
    if status:
        query = query.filter(FindingModel.status == status)
    if severity:
        query = query.filter(FindingModel.severity == severity)
    if state:
        query = query.filter(FindingModel.state == state)
    if confidence:
        query = query.filter(FindingModel.confidence == confidence)
    if category:
        query = query.filter(FindingModel.category == category)
    if resolution:
        query = query.filter(FindingModel.resolution == resolution)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    rows = [
        f for f in query.all()
        if not q or q.lower() in f"{f.title} {f.detail} {f.finding_id} {f.category}".lower()
    ]
    rows.sort(key=lambda f: (order.get(f.severity, 9), f.finding_id, f.id))
    response.headers["X-Total-Count"] = str(len(rows))
    return [_to_dict(f, runs[f.run_id]) for f in rows[offset:offset + limit]]


@router.get("/{row_id}")
def get_finding(row_id: str, db: Session = Depends(get_db)):
    expire_risk_acceptances(db)
    f = db.query(FindingModel).filter(FindingModel.id == row_id).one_or_none()
    if not f:
        raise HTTPException(404, "Achado não encontrado")
    run = db.query(ScanRun).filter(ScanRun.id == f.run_id).one_or_none()
    return {**_to_dict(f, run), "history": finding_history(db, f, run)}


class FindingUpdate(BaseModel):
    resolution: str
    resolutionNote: Optional[str] = None
    expiresInDays: Optional[int] = None  # só vale para risk_accepted


@router.patch("/{row_id}")
def update_finding(row_id: str, body: FindingUpdate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    if body.resolution not in RESOLUTIONS:
        raise HTTPException(400, f"resolution deve ser um de: {', '.join(sorted(RESOLUTIONS))}")
    if body.expiresInDays is not None and not (1 <= body.expiresInDays <= 730):
        raise HTTPException(400, "A validade do aceite deve ficar entre 1 e 730 dias.")
    if body.resolution == "risk_accepted" and not (body.resolutionNote or "").strip():
        raise HTTPException(400, "Aceitar o risco exige uma justificativa.")
    f = db.query(FindingModel).filter(FindingModel.id == row_id).one_or_none()
    if not f:
        raise HTTPException(404, "Achado não encontrado")
    f.resolution = body.resolution
    f.resolution_note = body.resolutionNote
    f.resolution_by = getattr(user, "email", None)
    f.resolution_expires_at = (
        datetime.now(timezone.utc) + timedelta(days=body.expiresInDays)
        if body.resolution == "risk_accepted" and body.expiresInDays else None
    )
    db.commit()
    db.refresh(f)
    run = db.query(ScanRun).filter(ScanRun.id == f.run_id).one_or_none()
    return _to_dict(f, run)
