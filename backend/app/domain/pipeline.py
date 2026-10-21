# Orquestra estático + dinâmico + probes ativos + IA num único resultado.
# Equivalente ao main() de scan.mjs, sem a parte de CLI/HTML.

from typing import Any

import httpx

from .active_probes import run_active_probes
from .ai_recommendations import enrich_with_ai
from .dynamic_analyzer import run_dynamic
from .endpoint_discovery import build_dynamic_finding, build_static_finding
from .generic_static import detect_stack, run_generic_static
from .models import OWASP_API, Finding
from .policy import evaluate_policy
from .scoring import score
from .soap_checks import run_soap_checks
from .spec_checks import run_spec_checks
from .static_analyzer import index_project, run_static


async def run_scan(target: dict, *, static: bool = True, dynamic: bool = True, ai: bool = True) -> dict[str, Any]:
    findings: list[Finding] = []
    modes: list[str] = []

    can_static = static and bool(target.get("projectPath"))
    if can_static:
        if detect_stack(target.get("projectPath")) == "nextjs":
            findings.extend(run_static(target))  # regras específicas de Next.js só onde fazem sentido
        findings.extend(run_generic_static(target))
        idx = index_project(target.get("projectPath"))
        if idx.files:
            findings.append(build_static_finding(target, idx))
        modes.append("estático")

    if dynamic:
        findings.extend(await run_dynamic(target))
        findings.extend(await run_active_probes(target))
        if target.get("baseUrl"):
            findings.extend(await run_spec_checks(target))
            findings.extend(await run_soap_checks(target))
        if target.get("baseUrl"):
            async with httpx.AsyncClient() as client:
                findings.append(await build_dynamic_finding(client, target))
        modes.append("dinâmico")

    if not findings:
        raise ValueError("Nada a analisar (habilite static e/ou dynamic).")

    for f in findings:
        if not f.owasp and f.id in OWASP_API:
            f.owasp = OWASP_API[f.id]

    result = score(findings)
    # category["findings"] guarda os objetos Finding só para uso interno do
    # scoring; o consumidor (API/DB/frontend) só precisa de score/contagens.
    for cat in result["categories"]:
        cat.pop("findings", None)

    ai_results = await enrich_with_ai(target, result, findings, disabled=not ai)
    result["ai"] = ai_results
    enabled_providers = [o["provider"] for o in ai_results if o.get("enabled")]
    if enabled_providers:
        modes.append("IA (" + " + ".join(enabled_providers) + ")")

    result["mode"] = " + ".join(modes)
    result["policy"] = evaluate_policy(findings)
    result["findings"] = [f.to_dict() for f in findings]
    return result
