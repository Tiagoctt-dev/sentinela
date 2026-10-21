# Avaliação de política de conformidade sobre os achados de um scan.
# Por ora só existe uma política embutida (não editável via API ainda) —
# a tela de Políticas mostra essa regra em modo leitura; CRUD de políticas
# customizadas fica pra depois.

from .models import STATUS, Finding

DEFAULT_POLICY = {
    "id": "default-owasp",
    "name": "Padrão OWASP API",
    "description": "Nenhum achado crítico é tolerado.",
    "scope": "Todos os projetos",
}


def evaluate_policy(findings: list[Finding]) -> dict:
    violations = [f for f in findings if f.status == STATUS.FAIL and f.severity == "CRITICAL"]
    return {
        "policyId": DEFAULT_POLICY["id"],
        "policyName": DEFAULT_POLICY["name"],
        "passed": not violations,
        "reason": DEFAULT_POLICY["description"],
        "violations": [f.id for f in violations],
    }
