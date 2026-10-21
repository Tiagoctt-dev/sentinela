# Domínio do scanner: severidades, categorias, status e a forma de um "achado".
# Porte de lib/models.mjs.

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Severity:
    key: str
    label: str
    weight: int
    order: int


SEVERITY: dict[str, Severity] = {
    "CRITICAL": Severity("CRITICAL", "Crítico", 40, 0),
    "HIGH": Severity("HIGH", "Alto", 25, 1),
    "MEDIUM": Severity("MEDIUM", "Médio", 15, 2),
    "LOW": Severity("LOW", "Baixo", 7, 3),
    "INFO": Severity("INFO", "Info", 0, 4),
}


@dataclass(frozen=True)
class Category:
    key: str
    label: str
    short: str


CATEGORY: dict[str, Category] = {
    "AUTHORIZATION": Category("AUTHORIZATION", "Autorização & Acesso", "Autorização"),
    "TOKEN_SESSION": Category("TOKEN_SESSION", "Token & Sessão", "Token/Sessão"),
    "OAUTH_OIDC": Category("OAUTH_OIDC", "OAuth · OIDC · PKCE", "OAuth/OIDC"),
    "TRANSPORT": Category("TRANSPORT", "Transporte (TLS/mTLS)", "Transporte"),
    "HEADERS": Category("HEADERS", "Cabeçalhos de Segurança", "Headers"),
    "INPUT_VALIDATION": Category("INPUT_VALIDATION", "Validação de Entrada", "Validação"),
    "INTEGRITY": Category("INTEGRITY", "Integridade de Requisição", "Integridade"),
    "INVENTORY": Category("INVENTORY", "Inventário de Endpoints", "Inventário"),
}

CATEGORY_ORDER = [
    "AUTHORIZATION", "TOKEN_SESSION", "OAUTH_OIDC",
    "INTEGRITY", "HEADERS", "INPUT_VALIDATION", "TRANSPORT", "INVENTORY",
]


class STATUS:
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


# Mapa achado → categoria do OWASP API Security Top 10 (2023).
OWASP_API: dict[str, str] = {
    "S-BOLA-01": "API1:2023", "S-AUTHZ-01": "API5:2023", "S-AUTHZ-02": "API5:2023",
    "D-AUTHZ-01": "API1:2023", "D-AUTHZ-02": "API1:2023",
    "S-TOKEN-01": "API2:2023", "S-TOKEN-02": "API2:2023", "S-OIDC-01": "API2:2023", "S-OIDC-02": "API2:2023",
    "S-INTEG-01": "API2:2023", "S-INTEG-02": "API5:2023", "D-INTEG-01": "API2:2023", "D-INTEG-02": "API5:2023",
    "S-HEAD-01": "API8:2023", "D-HEAD-01": "API8:2023", "D-INFO-01": "API8:2023",
    "S-INPUT-01": "API3:2023", "S-INPUT-02": "API2:2023",
    "S-TLS-01": "API8:2023", "S-TOKEN-03": "API2:2023", "D-TLS-01": "API8:2023",
    "D-OIDC-01": "API2:2023",
    "S-SEC-01": "API8:2023", "S-SEC-02": "API8:2023", "S-SEC-03": "API8:2023", "S-SEC-04": "API2:2023",
    "S-SEC-05": "API8:2023", "S-SEC-06": "API8:2023", "S-SEC-07": "API2:2023",
}


@dataclass
class Finding:
    id: str
    category: str
    title: str
    status: str
    severity: str = "INFO"
    detail: str = ""
    recommendation: str = ""
    evidence: str = ""
    source: str = "static"
    owasp: str = ""
    data: Optional[dict[str, Any]] = None
    ai_rec: Optional[dict[str, Any]] = field(default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "source": self.source,
            "owasp": self.owasp,
            "data": self.data,
            "aiRec": self.ai_rec,
        }


def finding(**kwargs) -> Finding:
    return Finding(**kwargs)


def pass_icon(status: str) -> str:
    return {"PASS": "✔", "FAIL": "✘", "WARN": "▲"}.get(status, "–")
