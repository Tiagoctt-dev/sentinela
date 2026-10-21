# "Achados" globais — visão consolidada dos findings do scan mais recente de
# cada alvo, com workflow de triagem (aberto/resolvido/risco aceito).

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.models import FindingModel, ScanRun
from ..db.session import get_db
from ..domain.policy_catalog import owasp_for_check
from .common import latest_scan_per_target

router = APIRouter(prefix="/api/findings", tags=["findings"])

RESOLUTIONS = {"open", "resolved", "risk_accepted"}


def _to_dict(f: FindingModel, run: ScanRun) -> dict:
    return {
        "rowId": f.id, "id": f.finding_id, "scanId": run.id, "targetId": run.target_id,
        "targetName": run.target_name, "category": f.category, "title": f.title, "status": f.status,
        "severity": f.severity, "detail": f.detail, "recommendation": f.recommendation,
        "evidence": f.evidence, "source": f.source, "owasp": f.owasp or owasp_for_check(f.finding_id), "data": f.data, "aiRec": f.ai_rec,
        "resolution": f.resolution, "resolutionNote": f.resolution_note, "createdAt": run.created_at.isoformat(),
    }


@router.get("")
def list_findings(
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    resolution: Optional[str] = None,
    targetId: Optional[str] = None,
    q: Optional[str] = None,
    onlyActionable: bool = True,
):
    latest = latest_scan_per_target(db)
    if targetId:
        latest = [r for r in latest if r.target_id == targetId]
    runs = {r.id: r for r in latest}
    if not runs:
        return []
    query = db.query(FindingModel).filter(FindingModel.run_id.in_(runs.keys()))
    if status:
        query = query.filter(FindingModel.status == status)
    if severity:
        query = query.filter(FindingModel.severity == severity)
    if resolution:
        query = query.filter(FindingModel.resolution == resolution)
    rows = query.all()

    out = []
    for f in rows:
        if onlyActionable and f.status not in ("FAIL", "WARN"):
            continue
        if q and q.lower() not in f"{f.title} {f.detail} {f.finding_id} {f.category}".lower():
            continue
        out.append(_to_dict(f, runs[f.run_id]))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    out.sort(key=lambda x: order.get(x["severity"], 9))
    return out


@router.get("/{row_id}")
def get_finding(row_id: str, db: Session = Depends(get_db)):
    f = db.query(FindingModel).filter(FindingModel.id == row_id).one_or_none()
    if not f:
        raise HTTPException(404, "Achado não encontrado")
    run = db.query(ScanRun).filter(ScanRun.id == f.run_id).one_or_none()
    return _to_dict(f, run)


class FindingUpdate(BaseModel):
    resolution: str
    resolutionNote: Optional[str] = None


@router.patch("/{row_id}")
def update_finding(row_id: str, body: FindingUpdate, db: Session = Depends(get_db)):
    if body.resolution not in RESOLUTIONS:
        raise HTTPException(400, f"resolution deve ser um de: {', '.join(sorted(RESOLUTIONS))}")
    f = db.query(FindingModel).filter(FindingModel.id == row_id).one_or_none()
    if not f:
        raise HTTPException(404, "Achado não encontrado")
    f.resolution = body.resolution
    f.resolution_note = body.resolutionNote
    db.commit()
    db.refresh(f)
    run = db.query(ScanRun).filter(ScanRun.id == f.run_id).one_or_none()
    return _to_dict(f, run)
