# Verificações básicas para serviços SOAP/legado: descobre o WSDL e avalia o
# que ele revela (exposição pública do contrato e política WS-Security).
# Só roda quando um WSDL é encontrado — não adiciona ruído a APIs REST.

import re
from typing import Optional

import httpx

from .models import STATUS, Finding, finding

WSDL_PATHS = ["?wsdl", "/?wsdl", "/service?wsdl", "/ws?wsdl", "/services?wsdl", "/soap?wsdl", "/Service.svc?wsdl", "/service.asmx?WSDL"]
TIMEOUT_S = 6.0
SECURITY_MARKERS = re.compile(r"UsernameToken|SignedParts|EncryptedParts|AsymmetricBinding|SymmetricBinding|TransportBinding|wss-|ws-securitypolicy|oasis-200401-wss", re.I)


async def _find_wsdl(client: httpx.AsyncClient, target: dict, base: str) -> tuple[Optional[str], str]:
    explicit = target.get("wsdlUrl")
    candidates = [explicit if str(explicit).startswith("http") else base + explicit] if explicit else [base + p for p in WSDL_PATHS]
    for url in candidates:
        try:
            res = await client.get(url, timeout=TIMEOUT_S, follow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        if res.status_code == 200 and re.search(r"<(?:\w+:)?definitions\b", res.text[:4000]):
            return url, res.text
    return None, ""


async def run_soap_checks(target: dict) -> list[Finding]:
    base = (target.get("baseUrl") or "").rstrip("/")
    async with httpx.AsyncClient() as client:
        url, text = await _find_wsdl(client, target, base)
    if not url:
        return []

    ops = len(set(re.findall(r"<(?:\w+:)?operation\s+name=\"([^\"]+)\"", text)))
    secured = bool(SECURITY_MARKERS.search(text))
    return [
        finding(
            id="D-SOAP-01", category="INVENTORY", severity="MEDIUM", owasp="API9:2023", source="dynamic",
            title="Contrato SOAP (WSDL) não está exposto publicamente", status=STATUS.WARN,
            detail=f"O WSDL está acessível sem autenticação e revela {ops} operação(ões) do serviço legado.",
            recommendation="Restringir o WSDL a redes/clientes autorizados (ou autenticar) — ele entrega ao atacante o mapa completo das operações.",
            evidence=f"GET {url}\n→ HTTP 200 · {ops} operação(ões) listadas",
        ),
        finding(
            id="D-SOAP-02", category="INTEGRITY", severity="HIGH", owasp="API2:2023", source="dynamic",
            title="Serviço SOAP declara política WS-Security",
            status=STATUS.PASS if secured else STATUS.WARN,
            detail=("O WSDL declara política de segurança de mensagem (WS-Security/SecurityPolicy)." if secured
                    else "Nenhuma política WS-Security (UsernameToken, assinatura, criptografia) declarada no WSDL."),
            recommendation="Exigir WS-Security (assinatura XML e/ou UsernameToken sobre TLS) e validar no servidor, não só declarar no contrato.",
            evidence=f"GET {url}",
        ),
    ]
