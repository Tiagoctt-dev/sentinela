# Políticas de conformidade: a regra de aprovação (gate) aplicada a cada scan e
# o catálogo OWASP API Security Top 10 (2023) com o que o Sentinela verifica
# em cada item e o estado atual real (achados dos scans mais recentes).

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db.models import FindingModel
from ..db.session import get_db
from ..domain.owasp_api_top10 import OWASP_API_TOP10
from ..domain.policy import DEFAULT_POLICY
from ..domain.policy_catalog import CHECKS, NEEDS_CONFIG, NOT_COVERED_NOTES, owasp_for_check
from .common import latest_scan_per_target

router = APIRouter(prefix="/api/policies", tags=["policies"])

# Cobertura honesta por item do Top 10. "parcial" = há verificação, mas ela não esgota o risco.
COVERAGE = {
    "API1:2023": ("coberto", None),
    "API2:2023": ("coberto", None),
    "API3:2023": ("coberto", None),
    "API4:2023": ("parcial", "Só mede rate limiting numa rajada de 20 requisições; não testa quotas por usuário nem endpoints caros."),
    "API5:2023": ("coberto", "O teste dinâmico de BFLA exige um usuário de papel comum cadastrado e as rotas administrativas configuradas no projeto."),
    "API6:2023": ("parcial", "Detecta fluxos sensíveis na spec sem limite documentado e testa força bruta no login; não simula abuso de regras de negócio (ex.: limite de transferências por conta)."),
    "API7:2023": ("parcial", "Testa SSRF por callback em parâmetros GET de URL; ainda não cobre parâmetros em corpo JSON (POST) nem cabeçalhos."),
    "API8:2023": ("coberto", None),
    "API9:2023": ("parcial", "Lista endpoints do código e da spec e procura rotas de debug/administração expostas; ainda não detecta versões antigas (v1, v2) esquecidas."),
    "API10:2023": ("nao_coberto", NOT_COVERED_NOTES["API10:2023"]),
}


@router.get("")
def list_policies():
    return [{**DEFAULT_POLICY, "status": "ativa", "editable": False}]


@router.get("/owasp")
def owasp_catalog(db: Session = Depends(get_db)):
    runs = {r.id: r for r in latest_scan_per_target(db)}
    findings = db.query(FindingModel).filter(FindingModel.run_id.in_(runs.keys())).all() if runs else []

    stats: dict[str, dict] = {}
    for f in findings:
        oid = f.owasp or owasp_for_check(f.finding_id)
        if not oid:
            continue
        s = stats.setdefault(oid, {"pass": 0, "fail": 0, "warn": 0, "open": 0, "openFindings": []})
        if f.status == "PASS":
            s["pass"] += 1
        elif f.status in ("FAIL", "WARN"):
            s["fail" if f.status == "FAIL" else "warn"] += 1
            if f.resolution == "open":
                s["open"] += 1
                s["openFindings"].append({
                    "rowId": f.id, "title": f.title, "severity": f.severity,
                    "targetName": runs[f.run_id].target_name,
                })

    items = []
    for o in OWASP_API_TOP10:
        coverage, note = COVERAGE[o["id"]]
        checks = [
            {"id": c["id"], "title": c["title"], "kind": c["kind"], "severity": c["severity"],
             "how": c["how"], "needsConfig": c["id"] in NEEDS_CONFIG}
            for c in CHECKS if c["owasp"] == o["id"]
        ]
        s = stats.get(o["id"], {"pass": 0, "fail": 0, "warn": 0, "open": 0, "openFindings": []})
        items.append({
            "id": o["id"], "name": o["nome"], "description": o["desc"],
            "coverage": coverage, "coverageNote": note, "checks": checks,
            "stats": {k: s[k] for k in ("pass", "fail", "warn", "open")},
            "openFindings": s["openFindings"][:5],
        })

    return {
        "gate": {
            "name": DEFAULT_POLICY["name"],
            "summary": "Um scan é reprovado se tiver qualquer achado CRÍTICO com status FALHA.",
            "verdicts": [
                {"label": "Conforme", "range": "score ≥ 85"},
                {"label": "Parcialmente conforme", "range": "score 60–84"},
                {"label": "Não conforme", "range": "score < 60"},
            ],
            "scoring": [
                "Cada categoria começa em 100 pontos.",
                "FALHA tira o peso cheio da severidade (crítico 40, alto 25, médio 15, baixo 7); ALERTA tira metade.",
                "Teto: uma falha crítica limita o score geral a 50; uma falha alta, a 70.",
            ],
        },
        "items": items,
        "summary": {
            "covered": sum(1 for i in items if i["coverage"] == "coberto"),
            "partial": sum(1 for i in items if i["coverage"] == "parcial"),
            "notCovered": sum(1 for i in items if i["coverage"] == "nao_coberto"),
            "total": len(items),
            "checks": len(CHECKS),
        },
    }
