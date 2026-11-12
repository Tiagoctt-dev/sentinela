import asyncio
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.models import FindingModel, ScanRun, TargetModel
from ..db.session import get_db
from .. import metrics, progress
from ..domain.pipeline import run_scan
from ..domain.sarif import to_sarif
from ..domain.triage import inherit_triage
from ..domain.routes_view import build_routes
from ..netguard import TargetNotAllowed, validate_url
from ..domain.policy_catalog import owasp_for_check
from ..domain.webhooks import fire_scan_completed, fire_scan_completed_github, fire_scan_completed_slack
from ..auth import get_current_user
from .routes_credentials import load_credentials
from .routes_targets import get_or_create_target, get_or_create_url_target

router = APIRouter(prefix="/api/scans", tags=["scans"])
logger = logging.getLogger("sentinela.scans")

SCAN_TIMEOUT_S = float(os.environ.get("SENTINELA_SCAN_TIMEOUT_S", "300"))
_slots: Optional[asyncio.Semaphore] = None


def _scan_slots() -> asyncio.Semaphore:
    global _slots
    if _slots is None:
        _slots = asyncio.Semaphore(int(os.environ.get("SENTINELA_MAX_CONCURRENT_SCANS", "3")))
    return _slots


# Projetos com scan em andamento neste processo: impede duas execuções simultâneas do mesmo alvo
# (que se sobrecarregariam e poderiam duplicar escritas de teste). Vale por processo.
_running: set[str] = set()

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class RunScanRequest(BaseModel):
    targetId: Optional[str] = None
    target: Optional[str] = None
    url: Optional[str] = None
    static: bool = True
    dynamic: bool = True
    ai: bool = True
    # "safe" = somente leitura: ignora a autorização de escrita do projeto (BOLA/BFLA com PUT/DELETE e mass assignment ficam "não executados").
    profile: str = "full"


def _finding_to_dict(f: FindingModel) -> dict:
    return {
        "rowId": f.id, "id": f.finding_id, "category": f.category, "title": f.title, "status": f.status,
        "severity": f.severity, "detail": f.detail, "recommendation": f.recommendation,
        "evidence": f.evidence, "source": f.source, "owasp": f.owasp or owasp_for_check(f.finding_id), "data": f.data,
        "state": f.state, "confidence": f.confidence, "asset": f.asset, "meta": f.meta,
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
        "createdBy": run.created_by, "origin": run.origin, "scope": run.scope,
        "findings": [_finding_to_dict(f) for f in findings],
    }


async def run_target_scan(db: Session, target_row: TargetModel, *, target_cfg: Optional[dict] = None,
                          static: bool = True, dynamic: bool = True, ai: bool = True,
                          created_by: Optional[str] = None, origin: str = "manual", profile: str = "full") -> dict:
    """Executa um scan completo e persiste — usado pela API e pelo agendador."""
    if target_row.id in _running:
        raise HTTPException(409, "Já existe um scan em andamento para este projeto. Aguarde ele terminar.")
    _running.add(target_row.id)
    started = time.monotonic()
    try:
        scan = await _execute_scan(db, target_row, target_cfg, static, dynamic, ai, created_by, origin, profile)
    except HTTPException as err:
        metrics.record_scan(origin, f"erro_{err.status_code}", time.monotonic() - started)
        logger.warning("scan falhou projeto=%s origem=%s status=%s detalhe=%s", target_row.id, origin, err.status_code, err.detail)
        raise
    finally:
        _running.discard(target_row.id)
    elapsed = time.monotonic() - started
    metrics.record_scan(origin, "ok", elapsed)
    logger.info("scan concluído id=%s projeto=%s origem=%s score=%s cobertura=%s%% duração=%.1fs",
                scan["id"], target_row.id, origin, scan["overall"], (scan.get("scope") or {}).get("coveragePct"), elapsed)
    return scan


def _steps_total(static: bool, dynamic: bool, ai: bool, has_code: bool) -> int:
    return (1 if static and has_code else 0) + (4 if dynamic else 0) + 1 + (1 if ai else 0)


async def _execute_scan(db: Session, target_row: TargetModel, target_cfg: Optional[dict], static: bool, dynamic: bool, ai: bool,
                        created_by: Optional[str], origin: str, profile: str = "full") -> dict:
    target_cfg = dict(target_cfg if target_cfg is not None else target_row.config)
    if profile == "safe":
        target_cfg["allowMutations"] = False
    try:
        creds = load_credentials(db, target_row.id)
    except ValueError as err:
        raise HTTPException(409, "Não foi possível ler as credenciais de teste deste projeto: a chave de criptografia mudou. "
                                 "Cadastre os usuários de teste de novo (ou restaure a chave SENTINELA_SECRET_KEY).") from err
    if creds:
        target_cfg["_credentials"] = creds

    try:
        target_cfg["baseUrl"] = validate_url(target_cfg["baseUrl"]) if target_cfg.get("baseUrl") else ""
    except TargetNotAllowed as err:
        raise HTTPException(400, str(err)) from err

    try:
        async with _scan_slots():
            progress.start(target_row.id, _steps_total(static, dynamic, ai, bool(target_cfg.get("projectPath"))))
            result = await asyncio.wait_for(
                run_scan(target_cfg, static=static, dynamic=dynamic, ai=ai, progress=lambda label: progress.step(target_row.id, label)),
                SCAN_TIMEOUT_S,
            )
    except asyncio.TimeoutError as err:
        raise HTTPException(504, f"O scan excedeu o limite de {int(SCAN_TIMEOUT_S)}s e foi interrompido.") from err
    except ValueError as err:
        raise HTTPException(400, str(err)) from err
    finally:
        progress.finish(target_row.id)

    run = ScanRun(
        target_id=target_row.id,
        target_name=target_cfg.get("name", target_row.name),
        mode=result["mode"],
        overall_score=result["overall"],
        verdict=result["verdict"]["label"],
        categories=result["categories"],
        totals={**result["totals"], "states": result["states"]},
        ai=result["ai"],
        policy=result["policy"],
        created_by=created_by, origin=origin, scope=result.get("scope"),
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
            state=f["state"], confidence=f["confidence"], asset=f["asset"], meta=f["meta"],
        )
        db.add(row)
        finding_rows.append(row)

    db.commit()
    db.refresh(run)
    inherit_triage(db, run, finding_rows)  # aceite de risco vigente do scan anterior continua valendo
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
        if f.state == "vulnerable" and f.severity in ("CRITICAL", "HIGH")
    ][:10]
    event_payload = {
        "id": scan_dict["id"], "targetName": scan_dict["targetName"], "mode": scan_dict["mode"],
        "overall": scan_dict["overall"], "verdict": scan_dict["verdict"], "totals": scan_dict["totals"],
        "policy": scan_dict["policy"], "createdAt": scan_dict["createdAt"],
        "scanUrl": f"{app_url}/scans/{scan_dict['id']}", "topFindings": top_findings,
        "scope": ({k: scan_dict["scope"][k] for k in ("mode", "coveragePct", "checksExecuted", "checksPlanned")} if scan_dict.get("scope") else None),
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

    if body.profile not in ("full", "safe"):
        raise HTTPException(400, "profile deve ser 'full' ou 'safe'.")
    return await run_target_scan(
        db, target_row, target_cfg=target_cfg, static=body.static, dynamic=body.dynamic, ai=body.ai,
        created_by=getattr(user, "email", None), origin="manual", profile=body.profile,
    )


@router.get("")
def list_scans(
    response: Response,
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    targetId: Optional[str] = None,
):
    q = db.query(ScanRun)
    if targetId:
        q = q.filter(ScanRun.target_id == targetId)
    response.headers["X-Total-Count"] = str(q.count())
    runs = q.order_by(ScanRun.created_at.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": r.id, "targetId": r.target_id, "targetName": r.target_name, "mode": r.mode,
            "overall": r.overall_score, "verdict": r.verdict, "totals": r.totals, "policy": r.policy,
            "createdAt": r.created_at.isoformat(),
            "createdBy": r.created_by, "origin": r.origin,
            "scope": ({"mode": r.scope.get("mode"), "coveragePct": r.scope.get("coveragePct")} if r.scope else None),
        }
        for r in runs
    ]


@router.get("/progress")
def scans_progress():
    """Scans em andamento neste servidor: etapa atual e contagem (o front consulta enquanto espera)."""
    return {"running": progress.running()}


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    findings = db.query(FindingModel).filter(FindingModel.run_id == run.id).all()
    return _run_to_dict(run, findings)


@router.get("/{scan_id}/sarif")
def scan_sarif(scan_id: str, db: Session = Depends(get_db)):
    """Exporta o scan em SARIF 2.1.0 (vulnerabilidades confirmadas e prováveis) para uso em pipelines e ferramentas de código."""
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    findings = db.query(FindingModel).filter(FindingModel.run_id == run.id).all()
    app_url = os.environ.get("PUBLIC_APP_URL", "http://localhost:5173").rstrip("/")
    return to_sarif(_run_to_dict(run, findings), app_url)


@router.get("/{scan_id}/routes")
def scan_routes(scan_id: str, db: Session = Depends(get_db)):
    """Rotas e verificações do scan (ver domain/routes_view.py para as definições)."""
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    rows = db.query(FindingModel).filter(FindingModel.run_id == run.id).all()
    return build_routes([{**_finding_to_dict(f), "rowId": f.id} for f in rows], run.scope)


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

    cur = {f.finding_id: f for f in db.query(FindingModel).filter(FindingModel.run_id == run.id).all()}
    old = {f.finding_id: f for f in db.query(FindingModel).filter(FindingModel.run_id == prev.id).all()}

    def brief(f: FindingModel) -> dict:
        return {"rowId": f.id, "id": f.finding_id, "title": f.title, "severity": f.severity, "status": f.status, "state": f.state}

    # Só estados com prova ou indício contam como problema; "não executado" não é "corrigido".
    bad = ("vulnerable", "likely")
    ran = ("vulnerable", "likely", "passed")
    new = [brief(f) for k, f in cur.items() if f.state in bad and (k not in old or old[k].state not in bad)]
    fixed = [brief(f) for k, f in old.items() if f.state in bad and k in cur and cur[k].state == "passed"]
    not_comparable = [brief(f) for k, f in old.items() if f.state in bad and (k not in cur or cur[k].state not in ran)]
    worse = [brief(f) for k, f in cur.items() if f.state == "vulnerable" and k in old and old[k].state == "likely"]
    persisting = sum(1 for k, f in cur.items() if f.state in bad and k in old and old[k].state in bad)
    return {
        "previous": {"id": prev.id, "createdAt": prev.created_at.isoformat(), "overall": prev.overall_score, "verdict": prev.verdict},
        "delta": run.overall_score - prev.overall_score,
        "new": new, "fixed": fixed, "worse": worse, "persisting": persisting, "notComparable": not_comparable,
    }


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.id == scan_id).one_or_none()
    if not run:
        raise HTTPException(404, "Scan não encontrado")
    db.delete(run)
    db.commit()
