# Políticas de conformidade: a regra de aprovação (gate) aplicada a cada scan e
# o catálogo OWASP API Security Top 10 (2023) com o que o Sentinela verifica
# em cada item e o estado atual real (achados dos scans mais recentes).

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db.models import FindingModel
from ..db.session import get_db
from ..domain.knowledge import cwe_ref, knowledge_for, owasp_ref
from ..domain.owasp_api_top10 import OWASP_API_TOP10
from ..domain.policy import DEFAULT_POLICY
from ..domain.policy_catalog import CHECKS, NEEDS_CONFIG, NOT_COVERED_NOTES, owasp_for_check
from .common import latest_scan_per_target

router = APIRouter(prefix="/api/policies", tags=["policies"])

# Cobertura declarada por item do Top 10. Critério (docs/politicas.md):
#   "coberto"     — há verificação com prova direta E ela cobre a superfície típica do risco sem depender de uma única rota;
#   "parcial"     — há verificação, mas limitada (rotas configuradas, heurística, um único caso ou só indício);
#   "nao_coberto" — nenhuma verificação.
# Nenhuma categoria é marcada "coberto" só porque existe uma política com o nome correspondente.
COVERAGE = {
    "API1:2023": ("parcial", "O BOLA dinâmico testa UMA rota informada no projeto, com dois usuários de teste e escrita autorizada. Rotas do tipo /recurso/{id} descobertas pela spec não são testadas automaticamente."),
    "API2:2023": ("parcial", "Cobre JWT (alg=none, segredo fraco, expiração), rota protegida sem token, rotas da spec sem credencial e brute force no login (indício). Não testa MFA, política de senha, recuperação de conta nem fluxos OAuth ao vivo."),
    "API3:2023": ("parcial", "Procura campos sensíveis por nome em respostas e testa mass assignment com UM campo e UM fluxo de cadastro. Não compara o contrato de resposta com o schema da spec."),
    "API4:2023": ("parcial", "Só mede 429 em uma rajada de 20 requisições (indício). Não testa quotas por usuário, paginação sem limite nem endpoints custosos."),
    "API5:2023": ("parcial", "Testa as rotas administrativas informadas e as que a spec nomeia como admin/internal/debug (apenas GET), com usuário comum. Funções administrativas com outros nomes não são vistas."),
    "API6:2023": ("parcial", "Avalia a documentação de limites em fluxos sensíveis e o brute force no login. Não simula abuso de regra de negócio (ex.: limite de transferências por conta)."),
    "API7:2023": ("parcial", "SSRF por callback em parâmetros GET com nome de URL. Não cobre parâmetros em corpo JSON, cabeçalhos nem SSRF cego sem retorno ao Sentinela. Exige que o alvo alcance o Sentinela."),
    "API8:2023": ("coberto", "Cabeçalhos de segurança, CORS, TLS, divulgação de versão, rotas de debug e, com código, segredos, TLS desligado e modo debug. Não avalia versão de TLS, cifras nem mensagens de erro verbosas."),
    "API9:2023": ("parcial", "Lista endpoints do código e da spec e procura rotas de debug expostas. Não detecta versões antigas (v1, v2) esquecidas nem hosts não documentados."),
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
        if f.state == "passed":
            s["pass"] += 1
        elif f.state in ("vulnerable", "likely"):
            s["fail" if f.state == "vulnerable" else "warn"] += 1
            if f.resolution == "open":
                s["open"] += 1
                s["openFindings"].append({
                    "rowId": f.id, "title": f.title, "severity": f.severity,
                    "targetName": runs[f.run_id].target_name,
                })

    items = []
    for o in OWASP_API_TOP10:
        coverage, note = COVERAGE[o["id"]]
        checks = []
        for c in CHECKS:
            if c["owasp"] != o["id"]:
                continue
            k = knowledge_for(c["id"]) or {}
            checks.append({
                "id": c["id"], "title": c["title"], "kind": c["kind"], "severity": c["severity"],
                "how": c["how"], "needsConfig": c["id"] in NEEDS_CONFIG,
                "proof": k.get("proof"), "objective": k.get("objective"), "prerequisites": k.get("prerequisites"),
                "passWhen": k.get("passWhen"), "failWhen": k.get("failWhen"), "limitations": k.get("limitations"),
                "severityReason": k.get("severityReason"),
                "references": [r for r in [owasp_ref(c["owasp"])] if r] + [cwe_ref(n) for n in k.get("cwe", [])],
            })
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
            "summary": "Um scan é reprovado se tiver qualquer vulnerabilidade crítica CONFIRMADA. Indícios críticos ficam como pendência de validação.",
            "verdicts": [
                {"label": "Conforme", "range": "score ≥ 85"},
                {"label": "Parcialmente conforme", "range": "score 60–84"},
                {"label": "Não conforme", "range": "score < 60"},
            ],
            "scoring": [
                "Cada categoria começa em 100 pontos.",
                "Vulnerabilidade confirmada tira o peso cheio da severidade (crítico 40, alto 25, médio 15, baixo 7); alerta parcial e indício tiram metade.",
                "Teto: só uma falha CONFIRMADA limita o score — crítica a 50, alta a 70. Verificações não executadas não alteram o score, mas reduzem a cobertura informada.",
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
