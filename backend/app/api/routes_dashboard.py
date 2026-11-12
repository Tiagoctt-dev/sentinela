# Dashboard: métricas calculadas só de dados persistidos (último scan de cada
# projeto + histórico de execuções). Nada é estimado; quando falta dado, o
# campo vem vazio e `missing` explica o que falta.
#
# Definições:
#   findings.bySeverity  — vulnerabilidades confirmadas e prováveis (estado vulnerable|likely) do último scan de cada projeto.
#   findings.byState     — todas as verificações do último scan de cada projeto, por estado.
#   coverage.avgPct      — média de (verificações executadas / verificações planejadas) dos últimos scans COM escopo registrado.
#   trend                — evolução do projeto selecionado entre execuções, só com scans que possuem escopo e estados.

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db.models import FindingModel, ScanRun
from ..db.session import get_db
from ..domain.routes_view import build_routes
from .common import latest_scan_per_target
from .routes_scans import _finding_to_dict

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
STATES = ("vulnerable", "likely", "inconclusive", "error", "passed", "not_run", "not_applicable")


@router.get("")
def dashboard(targetId: Optional[str] = None, db: Session = Depends(get_db)):
    latest = latest_scan_per_target(db)
    if targetId:
        latest = [r for r in latest if r.target_id == targetId]
    missing: list[str] = []

    by_sev = {s: 0 for s in SEVERITIES}
    by_state = {s: 0 for s in STATES}
    by_cat: dict[str, dict] = {}
    open_vuln = 0
    route_totals = {"routes": 0, "known": 0, "tested": 0, "pending": 0}
    coverage = []

    for run in latest:
        rows = db.query(FindingModel).filter(FindingModel.run_id == run.id).all()
        dicts = [{**_finding_to_dict(f), "rowId": f.id} for f in rows]
        for f in rows:
            if f.state in by_state:
                by_state[f.state] += 1
            if f.state in ("vulnerable", "likely"):
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
                c = by_cat.setdefault(f.category, {"category": f.category, "vulnerable": 0, "likely": 0})
                c[f.state] += 1
                if f.resolution == "open":
                    open_vuln += 1
        if run.scope:
            coverage.append(run.scope.get("coveragePct", 0))
            counts = build_routes(dicts, run.scope)["counts"]
            for k in route_totals:
                route_totals[k] += counts[k]

    if not latest:
        missing.append("Nenhum scan executado ainda — rode um scan para gerar os indicadores.")
    elif not coverage:
        missing.append("Os scans existentes são anteriores ao registro de escopo; rode um novo scan para medir a cobertura.")

    # evolução entre execuções
    trend, trend_note = [], None
    if targetId:
        runs = db.query(ScanRun).filter(ScanRun.target_id == targetId).order_by(ScanRun.created_at).limit(30).all()
        for r in runs:
            states = (r.totals or {}).get("states")
            if not states:
                continue
            trend.append({
                "scanId": r.id, "createdAt": r.created_at.isoformat(), "score": r.overall_score,
                "vulnerable": states.get("vulnerable", 0), "likely": states.get("likely", 0),
                "coveragePct": (r.scope or {}).get("coveragePct"), "mode": (r.scope or {}).get("mode"),
            })
        if len(trend) < 2:
            trend_note = "São necessárias ao menos 2 execuções do mesmo projeto para mostrar a evolução."
    else:
        trend_note = "Selecione um projeto para ver a evolução entre execuções."

    return {
        "projects": len(latest),
        "findings": {
            "bySeverity": by_sev, "byState": by_state, "openConfirmedOrLikely": open_vuln,
            "byCategory": sorted(by_cat.values(), key=lambda c: -(c["vulnerable"] + c["likely"])),
        },
        "coverage": {"avgPct": round(sum(coverage) / len(coverage)) if coverage else None, "scansWithScope": len(coverage)},
        "routes": route_totals if coverage else None,
        "trend": trend if len(trend) >= 2 else [],
        "trendNote": trend_note,
        "missing": missing,
    }
