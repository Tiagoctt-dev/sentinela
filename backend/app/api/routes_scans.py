import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.models import FindingModel, ScanRun, TargetModel
from ..db.session import get_db
from ..domain.pipeline import run_scan
from ..domain.policy_catalog import owasp_for_check
from ..domain.webhooks import fire_scan_completed, fire_scan_completed_github, fire_scan_completed_slack
from ..auth import get_current_user
from .routes_credentials import load_credentials
from .routes_targets import get_or_create_target, get_or_create_url_target

router = APIRouter(prefix="/api/scans", tags=["scans"])

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class RunScanRequest(BaseModel):
    targetId: Optional[str] = None
    target: Optional[str] = None
    url: Optional[str] = None
    static: bool = True
    dynamic: bool = True
    ai: bool = True


def _finding_to_dict(f: FindingModel) -> dict:
    return {
        "rowId": f.id, "id": f.finding_id, "category": f.category, "title": f.title, "status": f.status,
        "severity": f.severity, "detail": f.detail, "recommendation": f.recommendation,
        "evidence": f.evidence, "source": f.source, "owasp": f.owasp or owasp_for_check(f.finding_id), "data": f.data,
        "aiRec": f.ai_rec, "resolution": f.resolution, "resolutionNote": f.resolution_note,
    }


def _run_to_dict(run: ScanRun, findings: list[FindingModel]) -> dict:
    return {
        "id": run.id,
        "targetId": run.target_id,
        "targetName": run.target_name,
        "mode": run.mode,
        "overall": run.overall_score,
        "verdict": run.verdict,
        "categories": run.categories,
        "totals": run.totals,
        "ai": run.ai,
        "policy": run.policy,
        "createdAt": run.created_at.isoformat(),
        "createdBy": run.created_by, "origin": run.origin,
        "findings": [_finding_to_dict(f) for f in findings],
    }


async def run_target_scan(db: Session, target_row: TargetModel, *, target_cfg: Optional[dict] = None,
                          static: bool = True, dynamic: bool = True, ai: bool = True,
                          created_by: Optional[str] = None, origin: str = "manual") -> dict:
    """Executa um scan completo e persiste — usado pela API e pelo agendador."""
    target_cfg = dict(target_cfg if target_cfg is not None else target_row.config)
    creds = load_credentials(db, target_row.id)
    if creds:
        target_cfg["_credentials"] = creds

    try:
        result = await run_scan(target_cfg, static=static, dynamic=dynamic, ai=ai)
    except ValueError as err:
        raise HTTPException(400, str(err)) from err

    run = ScanRun(
        target_id=target_row.id,
        target_name=target_cfg.get("name", target_row.name),
        mode=result["mode"],
        overall_score=result["overall"],
        verdict=result["verdict"]["label"],
        categories=result["categories"],
        totals=result["totals"],
        ai=result["ai"],
        policy=result["policy"],
        created_by=created_by, origin=origin,
    )
    db.add(run)
    db.flush()

    finding_rows = []
    for f in result["findings"]:
        row = FindingModel(
            run_id=run.id, finding_id=f["id"], category=f["category"], title=f["title"],
            status=f["status"], severity=f["severity"], detail=f["detail"],
            recommendation=f["recommendation"], evidence=f["evidence"], source=f["source"],
            owasp=f["owasp"] or owasp_for_check(f["id"]), data=f["data"], ai_rec=f["aiRec"],
        )
        db.add(row)
        finding_rows.append(row)

    db.commit()
    db.refresh(run)
    scan_dict = _run_to_dict(run, finding_rows)

    app_url = os.environ.get("PUBLIC_APP_URL", "http://localhost:5173").rstrip("/")
    top_findings = [
        {
            "id": f.finding_id, "title": f.title, "severity": f.severity, "status": f.status,
            "category": f.category, "owasp": f.owasp, "detail": f.detail,
            "evidence": (f.evidence or "")[:500], "recommendation": f.recommendation,
            "url": f"{app_url}/achados/{f.id}",
        }
        for f in sorted(finding_rows, key=lambda r: SEVERITY_ORDER.get(r.severity, 9))
        if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")
    ][:10]
    event_payload = {
        "id": scan_dict["id"], "targetName": scan_dict["targetName"], "mode": scan_dict["mode"],
        "overall": scan_dict["overall"], "verdict": scan_dict["verdict"], "totals": scan_dict["totals"],
        "policy": scan_dict["policy"], "createdAt": scan_dict["createdAt"],
        "scanUrl": f"{app_url}/scans/{scan_dict['id']}", "topFindings": top_findings,
    }
    await fire_scan_completed(db, event_payload)
    await fire_scan_completed_slack(db, event_payload)
    await fire_scan_completed_github(db, event_payload, finding_rows)

    return scan_dict


@router.post("")
async def create_scan(body: RunScanRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    if body.targetId:
        target_row = db.query(TargetModel).filter(TargetModel.id == body.targetId).one_or_none()
        if not target_row:
            raise HTTPException(404, "Alvo não encontrado")
        if target_row.source == "file":
            target_row = get_or_create_target(db, target_row.name)  # ressincroniza com o JSON
        target_cfg = dict(target_row.config)
        if body.url:
            target_cfg["baseUrl"] = body.url
    elif body.target:
        target_row = get_or_create_target(db, body.target)
        target_cfg = dict(target_row.config)
        if body.url:
            target_cfg["baseUrl"] = body.url
    elif body.url:
        target_row = get_or_create_url_target(db, body.url)
        target_cfg = dict(target_row.config)
    else:
        raise HTTPException(400, "Informe 'targetId', 'target' (alvo de exemplo) ou 'url' (scan avulso).")

    return await run_target_scan(
        db, target_row, target_cfg=target_cfg, static=body.static, dynamic=body.dynamic, ai=body.ai,
        created_by=getattr(user, "email", None), origin="manual",
    )


@router.get("")
def list_scans(db: Session = Depends(get_db), limit: int = 50, targetId: Optional[str] = None):
    q = db.query(ScanRun)
    if targetId:
        q = q.filter(ScanRun.target_id == targetId)
    runs = q.order_by(ScanRun.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id, "targetId": r.target_id, "targetName": r.target_name, "mode": r.mode,
            "overall": r.overall_score, "verdict": r.verdict, "totals": r.totals, "policy": r.policy,
            "createdAt": r.created_at.isoformat(),
            "createdBy": r.created_by, "origin": r.origin,
        }
        for r in runs
    ]


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    findings = db.query(FindingModel).filter(FindingModel.run_id == run.id).all()
    return _run_to_dict(run, findings)


@router.get("/{scan_id}/compare")
def compare_scan(scan_id: str, db: Session = Depends(get_db)):
    """Compara o scan com o anterior do mesmo projeto: o que piorou, o que foi corrigido."""
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    prev = (
        db.query(ScanRun)
        .filter(ScanRun.target_id == run.target_id, ScanRun.created_at < run.created_at)
        .order_by(ScanRun.created_at.desc())
        .first()
    )
    if not prev:
        return {"previous": None}

    bad = ("FAIL", "WARN")
    cur = {f.finding_id: f for f in db.query(FindingModel).filter(FindingModel.run_id == run.id).all()}
    old = {f.finding_id: f for f in db.query(FindingModel).filter(FindingModel.run_id == prev.id).all()}

    def brief(f: FindingModel) -> dict:
        return {"rowId": f.id, "id": f.finding_id, "title": f.title, "severity": f.severity, "status": f.status}

    new = [brief(f) for k, f in cur.items() if f.status in bad and (k not in old or old[k].status not in bad)]
    fixed = [brief(f) for k, f in old.items() if f.status in bad and (k not in cur or cur[k].status not in bad)]
    worse = [brief(f) for k, f in cur.items() if f.status == "FAIL" and k in old and old[k].status == "WARN"]
    persisting = sum(1 for k, f in cur.items() if f.status in bad and k in old and old[k].status in bad)
    return {
        "previous": {"id": prev.id, "createdAt": prev.created_at.isoformat(), "overall": prev.overall_score, "verdict": prev.verdict},
        "delta": run.overall_score - prev.overall_score,
        "new": new, "fixed": fixed, "worse": worse, "persisting": persisting,
    }


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    db.delete(run)
    db.commit()
