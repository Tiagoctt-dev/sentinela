# Classificação dos resultados: converte o "status" bruto de cada probe em
# estado + confiança, anexa o texto editorial e o ativo afetado.
#
# Regras (documentadas em docs/classificacao.md):
#   status FAIL  + proof "confirmed"  -> vulnerable / confirmed
#   status FAIL  + proof "indicative" -> likely     / indicative
#   status WARN  + proof "confirmed"  -> vulnerable / confirmed (alerta parcial: peso menor)
#   status WARN  + proof "indicative" -> likely     / indicative
#   status WARN com HTTP 404 ("rota não encontrada") -> inconclusive (não prova nada)
#   status PASS                       -> passed (somente dentro do escopo verificado)
#   status SKIP  -> error | not_run | not_applicable | inconclusive, conforme o motivo
# Ausência de evidência nunca vira "passed".

import re
from typing import Any, Optional
from urllib.parse import urlparse

from .knowledge import ENV_NOTES, cwe_ref, knowledge_for, owasp_ref
from .models import STATE, STATUS, Finding

ERROR_HINTS = ("falha ao requisitar", "não consegui alcançar", "não está respondendo")
NOT_APPLICABLE_HINTS = ("não se aplica", "não é hmac", "nenhuma rota de api identificada")
NOT_RUN_HINTS = ("cadastre", "informe", "configure", "sem usuário", "pulad", "não encontrada", "nenhuma spec", "nenhuma rota get", "projeto não encontrado", "não encontrei código")
NOT_FOUND_HINTS = ("404", "rota não encontrada", "não encontrada no app")

_REQ_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", re.M)
_HTTP = re.compile(r"HTTP\s+(\d{3})")


def _skip_state(f: Finding) -> str:
    text = f"{f.detail} {f.title}".lower()
    if f.id in ("D-ENV-00", "D-AUTH-00") or any(h in text for h in ERROR_HINTS):
        return STATE.ERROR
    if any(h in text for h in NOT_APPLICABLE_HINTS):
        return STATE.NOT_APPLICABLE
    if f.id == "S-ENV-00" or any(h in text for h in NOT_RUN_HINTS):
        return STATE.NOT_RUN
    return STATE.INCONCLUSIVE


def derive_state(f: Finding) -> tuple[str, str]:
    """(state, confidence). Respeita state/confidence já definidos pelo probe."""
    if f.state:
        return f.state, f.confidence or ("confirmed" if f.state == STATE.VULNERABLE else "indicative" if f.state == STATE.LIKELY else "none")

    k = knowledge_for(f.id)
    proof = (k or {}).get("proof", "indicative")
    text = f"{f.detail}".lower()

    if f.status == STATUS.PASS:
        return STATE.PASSED, "none"
    if f.status == STATUS.SKIP:
        return _skip_state(f), "none"
    if f.status == STATUS.WARN and any(h in text for h in NOT_FOUND_HINTS):
        return STATE.INCONCLUSIVE, "none"
    if proof == "confirmed":
        return STATE.VULNERABLE, "confirmed"
    return STATE.LIKELY, "indicative"


def infer_asset(f: Finding, base_url: str = "") -> Optional[dict[str, Any]]:
    asset = dict(f.asset) if f.asset else {}
    m = _REQ_LINE.search(f.evidence or "")
    if m and not asset.get("path"):
        asset["method"] = m.group(1)
        parsed = urlparse(m.group(2))
        asset["path"] = parsed.path or "/"
        asset["url"] = m.group(2)
        if parsed.query:
            asset["param"] = parsed.query.split("=")[0]
    h = _HTTP.search(f.evidence or "")
    if h and "httpStatus" not in asset:
        asset["httpStatus"] = int(h.group(1))
    if base_url and "host" not in asset:
        asset["host"] = urlparse(base_url).netloc
    return asset or None


def _references(f: Finding, k: Optional[dict]) -> list[dict]:
    refs = []
    o = owasp_ref(f.owasp)
    if o:
        refs.append(o)
    for n in (k or {}).get("cwe", []):
        refs.append(cwe_ref(n))
    return refs


def apply(f: Finding, base_url: str = "") -> Finding:
    state, confidence = derive_state(f)
    f.state, f.confidence = state, confidence

    # status legado coerente com o estado
    if state == STATE.LIKELY:
        f.status = STATUS.WARN
    elif state in (STATE.INCONCLUSIVE, STATE.ERROR, STATE.NOT_RUN, STATE.NOT_APPLICABLE):
        f.status = STATUS.SKIP
    elif state == STATE.PASSED:
        f.status = STATUS.PASS

    f.asset = infer_asset(f, base_url)

    k = knowledge_for(f.id)
    meta: dict[str, Any] = dict(f.meta or {})
    meta["policyId"] = f.id
    if k:
        meta.update({
            "summary": k["summary"], "technical": k["technical"], "impact": k["impact"],
            "exploitation": k["exploitation"], "prerequisites": k["prerequisites"],
            "passWhen": k["passWhen"], "failWhen": k["failWhen"], "limitations": k["limitations"],
            "severityReason": k["severityReason"], "proof": k["proof"],
        })
    elif f.id in ENV_NOTES:
        meta["summary"] = ENV_NOTES[f.id]
    meta["references"] = _references(f, k)

    if state in (STATE.VULNERABLE, STATE.LIKELY):
        meta["headline"] = (k or {}).get("summary") or f.title
    elif state == STATE.PASSED:
        meta["headline"] = f.title
        meta["scopeNote"] = "Aprovado dentro do escopo efetivamente verificado — não é garantia de ausência da falha."
    else:
        meta["headline"] = f.title
        meta["scopeNote"] = "Esta verificação não produziu evidência suficiente para aprovar nem reprovar."
    f.meta = meta
    return f


def classify_all(findings: list[Finding], base_url: str = "") -> list[Finding]:
    return [apply(f, base_url) for f in findings]
