# Discovery de endpoints — mapeia a superfície de API do alvo automaticamente,
# em vez de depender só do que foi digitado manualmente no JSON do alvo.
# Cobre OWASP API9:2023 (Improper Inventory Management): endpoints "shadow"/
# esquecidos que existem no código ou na spec, mas não estão documentados no
# target, são sinalizados para revisão.
#
# Duas fontes:
#  - estática: varre o código do projeto-alvo por rotas Next.js
#    (src/app/api/**/route.ts) e handlers Express (app.get/router.post/...).
#  - dinâmica: sonda locais conhecidos de spec OpenAPI/Swagger no app rodando
#    e extrai os paths documentados.

import re
from typing import Optional

import httpx

from .models import STATUS, Finding, finding
from .static_analyzer import Index

METHOD_RE = re.compile(
    r"\b(?:app|router)\.(get|post|put|delete|patch|options)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    re.I,
)

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/api-docs.json",
    "/swagger/v1/swagger.json", "/.well-known/openapi.json", "/v3/api-docs",
]


def _next_route_to_path(rel: str) -> Optional[str]:
    m = re.match(r"src/app/(api/.+)/route\.(ts|js)$", rel)
    if not m:
        return None
    segments = [seg for seg in m.group(1).split("/") if not re.match(r"^\(.*\)$", seg)]
    path = "/" + "/".join(seg.replace("[", "{").replace("]", "}") for seg in segments)
    return path


def discover_static_endpoints(index: Index) -> list[dict]:
    found: dict[str, set[str]] = {}

    for f in index.files:
        path = _next_route_to_path(f.rel)
        if path:
            for m in re.finditer(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|OPTIONS)\b", f.text):
                found.setdefault(path, set()).add(m.group(1).upper())
            if path not in found:
                found[path] = set()

    for f in index.files:
        for m in METHOD_RE.finditer(f.text):
            method, path = m.group(1).upper(), m.group(2)
            if not path.startswith("/"):
                continue
            found.setdefault(path, set()).add(method)

    return [{"path": p, "methods": sorted(methods) or ["?"]} for p, methods in sorted(found.items())]


def _extract_openapi_paths(spec: dict) -> list[dict]:
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    verbs = {"get", "post", "put", "delete", "patch", "options", "head"}
    out = []
    for path, ops in paths.items():
        methods = sorted(k.upper() for k in ops.keys() if k.lower() in verbs) if isinstance(ops, dict) else []
        out.append({"path": path, "methods": methods or ["?"]})
    return sorted(out, key=lambda e: e["path"])


async def discover_dynamic_endpoints(client: httpx.AsyncClient, base: str) -> tuple[Optional[str], list[dict]]:
    for spec_path in SPEC_PATHS:
        try:
            res = await client.get(base + spec_path, timeout=6.0, follow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        if res.status_code != 200:
            continue
        try:
            spec = res.json()
        except ValueError:
            continue
        eps = _extract_openapi_paths(spec)
        if eps:
            return spec_path, eps
    return None, []


def _configured_paths(target: dict) -> set[str]:
    ep = target.get("endpoints") or {}
    configured: set[str] = set()
    for v in ep.values():
        if isinstance(v, str):
            configured.add(v)
        elif isinstance(v, list):
            configured.update(v)
    auth = target.get("auth") or {}
    for key in ("register", "login", "protectedProbe"):
        if auth.get(key):
            configured.add(auth[key])
    return configured


def build_static_finding(target: dict, index: Index) -> Finding:
    endpoints = discover_static_endpoints(index)
    configured = _configured_paths(target)
    unconfigured = [e for e in endpoints if e["path"] not in configured]
    return finding(
        id="S-DISC-01", category="INVENTORY", severity="INFO", owasp="API9:2023", source="static",
        title="Discovery de endpoints (código)",
        status=STATUS.PASS if endpoints else STATUS.SKIP,
        detail=(f"{len(endpoints)} endpoint(s) identificados no código." +
                (f" {len(unconfigured)} não constam no target configurado — revise se são intencionais (shadow/zombie API)."
                 if unconfigured else "")
                if endpoints else "Nenhuma rota de API identificada no código do projeto."),
        recommendation="Mantenha o inventário de endpoints (target JSON) sincronizado com o código para não deixar rotas fora do radar de segurança.",
        evidence=f"{len(endpoints)} endpoint(s) · {len(unconfigured)} fora do inventário",
        data={"type": "discovery", "source": "static", "endpoints": endpoints, "unconfigured": [e["path"] for e in unconfigured]},
    )


async def build_dynamic_finding(client: httpx.AsyncClient, target: dict) -> Finding:
    base = (target.get("baseUrl") or "").rstrip("/")
    spec_path, endpoints = await discover_dynamic_endpoints(client, base)
    configured = _configured_paths(target)
    unconfigured = [e for e in endpoints if e["path"] not in configured]
    return finding(
        id="D-DISC-01", category="INVENTORY", severity="LOW", owasp="API9:2023", source="dynamic",
        title="Discovery de endpoints (spec OpenAPI/Swagger)",
        status=(STATUS.SKIP if not endpoints
                else STATUS.WARN if unconfigured else STATUS.PASS),
        detail=(f"Nenhuma spec OpenAPI/Swagger encontrada nos caminhos conhecidos ({', '.join(SPEC_PATHS)})."
                if not endpoints
                else f"Spec encontrada em {spec_path}: {len(endpoints)} endpoint(s) documentados." +
                (f" {len(unconfigured)} não constam no target configurado — possíveis shadow/zombie APIs: " +
                 ", ".join(e["path"] for e in unconfigured[:8]) + ("…" if len(unconfigured) > 8 else "") + "."
                 if unconfigured else " Todos já estão no inventário do target.")),
        recommendation="Toda API documentada na spec deve estar mapeada e monitorada; specs desatualizadas ou endpoints fora do inventário são sinal de API9:2023 (Improper Inventory Management).",
        evidence=f"{len(endpoints)} endpoint(s) · {len(unconfigured)} fora do inventário" if endpoints else "spec não encontrada",
        data={"type": "discovery", "source": "dynamic", "specPath": spec_path, "endpoints": endpoints, "unconfigured": [e["path"] for e in unconfigured]},
    )
