# Estatísticas agregadas pra a barra de cards da tela de Scans e badges da sidebar.

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db.models import FindingModel, ScanRun
from ..db.session import get_db
from .common import latest_scan_per_target

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    latest = latest_scan_per_target(db)

    score_avg = round(sum(r.overall_score for r in latest) / len(latest)) if latest else None

    criticos_abertos = 0
    endpoints = set()
    if latest:
        run_ids = [r.id for r in latest]
        findings = db.query(FindingModel).filter(FindingModel.run_id.in_(run_ids)).all()
        for f in findings:
            if f.status == "FAIL" and f.severity == "CRITICAL" and f.resolution == "open":
                criticos_abertos += 1
            if f.category == "INVENTORY" and isinstance(f.data, dict):
                for e in f.data.get("endpoints") or []:
                    if isinstance(e, dict) and e.get("path"):
                        endpoints.add((f.run_id, e["path"]))

    last_run = db.query(ScanRun).order_by(ScanRun.created_at.desc()).first()

    return {
        "scoreAvg": score_avg,
        "criticosAbertos": criticos_abertos,
        "endpointsCobertos": len(endpoints),
        "totalScans": db.query(ScanRun).count(),
        "totalProjects": len(latest),
        "lastScan": (
            {"id": last_run.id, "targetName": last_run.target_name, "createdAt": last_run.created_at.isoformat()}
            if last_run else None
        ),
    }
