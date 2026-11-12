# Avaliação da política de conformidade sobre os achados de um scan.
# Por ora só existe uma política embutida (não editável via API).
#
# Regra: o scan é reprovado se houver achado CRÍTICO com vulnerabilidade
# CONFIRMADA. Indícios críticos (estado "likely") não reprovam sozinhos, mas
# são listados em `pending` para validação manual.

from .models import STATE, Finding

DEFAULT_POLICY = {
    "id": "default-owasp",
    "name": "Padrão OWASP API",
    "description": "Nenhuma vulnerabilidade crítica confirmada é tolerada.",
    "scope": "Todos os projetos",
}


def evaluate_policy(findings: list[Finding]) -> dict:
    violations = [f for f in findings if f.state == STATE.VULNERABLE and f.severity == "CRITICAL"]
    pending = [f for f in findings if f.state == STATE.LIKELY and f.severity == "CRITICAL"]
    return {
        "policyId": DEFAULT_POLICY["id"],
        "policyName": DEFAULT_POLICY["name"],
        "passed": not violations,
        "reason": DEFAULT_POLICY["description"],
        "violations": [f.id for f in violations],
        "pending": [f.id for f in pending],
    }
