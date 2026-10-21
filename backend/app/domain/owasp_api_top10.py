# OWASP API Security Top 10 (2023) — taxonomia oficial usada como base de
# conhecimento do scanner. Alimenta a camada de IA como contexto.
# Referência: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
# Porte de lib/owasp-api-top10.mjs.

OWASP_API_TOP10 = [
    {"id": "API1:2023", "nome": "Broken Object Level Authorization (BOLA)",
     "desc": "Um usuário acessa objetos de outro manipulando o identificador. Exige checar o dono (userId) em toda leitura/escrita de objeto."},
    {"id": "API2:2023", "nome": "Broken Authentication",
     "desc": "Falhas em login, tokens ou sessões que permitem assumir a identidade de outro (JWT mal validado, tokens sem expiração, credenciais fracas)."},
    {"id": "API3:2023", "nome": "Broken Object Property Level Authorization",
     "desc": "Leitura ou escrita de propriedades que o usuário não deveria ver/editar (excessive data exposure + mass assignment)."},
    {"id": "API4:2023", "nome": "Unrestricted Resource Consumption",
     "desc": "Ausência de rate limiting/quotas, abrindo espaço para abuso, DoS e custo (endpoints caros sem limite)."},
    {"id": "API5:2023", "nome": "Broken Function Level Authorization (BFLA)",
     "desc": "Falta de checagem de papel/permissão em funções (usuário comum alcançando rota administrativa)."},
    {"id": "API6:2023", "nome": "Unrestricted Access to Sensitive Business Flows",
     "desc": "Fluxos de negócio sensíveis (compra, transferência, cadastro) sem proteção contra automação/abuso."},
    {"id": "API7:2023", "nome": "Server Side Request Forgery (SSRF)",
     "desc": "A API busca uma URL fornecida pelo usuário sem validar, permitindo alcançar recursos internos."},
    {"id": "API8:2023", "nome": "Security Misconfiguration",
     "desc": "Cabeçalhos de segurança ausentes, CORS frouxo, TLS fraco, mensagens de erro verbosas, defaults inseguros."},
    {"id": "API9:2023", "nome": "Improper Inventory Management",
     "desc": "APIs ou versões esquecidas/não documentadas ainda expostas (shadow e zombie APIs)."},
    {"id": "API10:2023", "nome": "Unsafe Consumption of APIs",
     "desc": "Confiar cegamente nos dados de APIs de terceiros consumidas, sem validar."},
]


def owasp_context_text() -> str:
    return "\n".join(f"- {o['id']} — {o['nome']}: {o['desc']}" for o in OWASP_API_TOP10)
