# Visão "Rotas e verificações" de um scan: para cada rota, quais verificações a
# alcançaram e qual foi o resultado de cada uma. É derivada EXCLUSIVAMENTE dos
# achados persistidos (asset + observações), sem inventar rotas nem resultados.
#
# Definições (usadas também nos totais, para que lista e contadores nunca divirjam):
#   - rota conhecida: aparece na spec OpenAPI, no código (S-DISC-01) ou na configuração do projeto;
#   - rota testada: ao menos uma verificação obteve resposta dela (observação com HTTP ou achado com ativo);
#   - rota pendente: conhecida, mas nenhuma verificação a alcançou;
#   - caminhos sondados que não existem (ex.: /.env respondendo 404) NÃO são rotas: só aparecem se expostos;
#   - estado da rota: o pior estado entre as verificações que a alcançaram
#     (vulnerable > likely > error > inconclusive > passed). "Aprovada" significa
#     "nenhuma das verificações executadas encontrou falha" — não que a rota seja segura.

from typing import Any

SEVERITY_RANK = {"vulnerable": 5, "likely": 4, "error": 3, "inconclusive": 2, "passed": 1}
GLOBAL_PATH = "/"

# Rótulo do resultado de cada observação por rota -> estado
OUTCOME_TO_STATE = {
    "exposed": "vulnerable", "sensitive": "vulnerable", "ssrf_confirmed": "vulnerable",
    "denied": "passed", "clean": "passed", "no_callback": "inconclusive", "accepted": "likely", "throttled": "passed",
    "undocumented": "likely", "documented": "passed", "not_json": "inconclusive", "inconclusive": "inconclusive", "error": "error",
}


def _norm(path: str) -> str:
    return (path or "/").split("?")[0] or "/"


def build_routes(findings: list[dict], scope: dict | None) -> dict[str, Any]:
    routes: dict[tuple[str, str], dict[str, Any]] = {}

    def route(method: str, path: str) -> dict[str, Any]:
        key = (method.upper(), _norm(path))
        return routes.setdefault(key, {"method": key[0], "path": key[1], "discovered": False, "sources": set(), "checks": []})

    # 1) descobertas (spec / código / configuração)
    for f in findings:
        d = f.get("data") or {}
        if d.get("type") == "discovery":
            for e in d.get("endpoints", []):
                for m in e.get("methods", ["GET"]):
                    r = route(m if m != "?" else "GET", e["path"])
                    r["discovered"] = True
                    r["sources"].add("spec" if d.get("source") == "dynamic" else "código")
    # 2) verificações com observações por rota
    for f in findings:
        if f["state"] in ("not_run", "not_applicable") and not f.get("asset"):
            continue
        d = f.get("data") or {}
        entry_base = {"checkId": f["id"], "title": f["title"], "findingRowId": f.get("rowId"), "severity": f["severity"]}
        observations = d.get("observations")
        if observations:
            grouped: dict[tuple, dict] = {}
            for o in observations:
                if f["id"] == "D-EXPO-01" and o.get("outcome") != "exposed":
                    continue  # caminho sondado que não existe: não é uma rota do sistema
                k = (o.get("method", "GET"), o.get("path", GLOBAL_PATH), o.get("outcome"), o.get("httpStatus"), o.get("param"))
                grouped.setdefault(k, {**o, "count": 0})["count"] += 1
            for o in grouped.values():
                st = OUTCOME_TO_STATE.get(o.get("outcome"), "inconclusive")
                if f["state"] == "not_run":
                    st = "not_run"
                r = route(o.get("method", "GET"), o.get("path", GLOBAL_PATH))
                note = (o.get("param") and f"parâmetro {o['param']}") or (", ".join(o.get("fields", [])) or None)
                if o["count"] > 1:
                    note = f"{note + ' · ' if note else ''}{o['count']} tentativas iguais"
                r["checks"].append({**entry_base, "state": st, "httpStatus": o.get("httpStatus"), "note": note})
                r["sources"].add("configuração" if not r["discovered"] else "spec")
        elif f.get("asset") and f["asset"].get("path") is not None:
            a = f["asset"]
            r = route(a.get("method", "GET"), a["path"])
            r["checks"].append({**entry_base, "state": f["state"], "httpStatus": a.get("httpStatus"), "note": None})
            if not r["discovered"]:
                r["sources"].add("configuração" if a["path"] != GLOBAL_PATH else "alvo")

    # 3) estado por rota
    items = []
    for r in routes.values():
        executed = [c for c in r["checks"] if c["state"] in SEVERITY_RANK]
        worst = max((c["state"] for c in executed), key=lambda s: SEVERITY_RANK[s], default=None)
        tested = any(c["httpStatus"] is not None or c["state"] in ("vulnerable", "likely", "passed") for c in r["checks"])
        if worst:
            state = worst
        elif r["checks"] and all(c["state"] == "not_run" for c in r["checks"]):
            state = "not_run"
        else:
            state = "not_tested"
        items.append({
            "method": r["method"], "path": r["path"], "discovered": r["discovered"], "tested": tested,
            "state": state, "sources": sorted(r["sources"]), "checks": r["checks"],
            "label": "Alvo (raiz)" if r["path"] == GLOBAL_PATH else None,
        })
    order = {"vulnerable": 0, "likely": 1, "error": 2, "inconclusive": 3, "not_tested": 4, "not_run": 5, "passed": 6}
    items.sort(key=lambda i: (order.get(i["state"], 9), i["path"], i["method"]))

    check_counts: dict[str, int] = {}
    for i in items:
        for c in i["checks"]:
            check_counts[c["state"]] = check_counts.get(c["state"], 0) + 1
    for i in items:
        i["known"] = i["discovered"] or "configuração" in i["sources"]
    known = [i for i in items if i["known"]]
    return {
        "routes": items,
        "counts": {
            "routes": len(items),
            "known": len(known),
            "tested": sum(1 for i in known if i["tested"]),
            "pending": sum(1 for i in known if not i["tested"]),
            "byState": {s: sum(1 for i in items if i["state"] == s) for s in ("vulnerable", "likely", "error", "inconclusive", "passed", "not_run", "not_tested")},
            "checks": check_counts,
        },
        "pendingChecks": (scope or {}).get("notRun", []),
        "notApplicableChecks": (scope or {}).get("notApplicable", []),
    }
