# Converte a lista de achados em score por categoria e score geral.
# Modelo transparente: cada categoria começa em 100 e perde pontos por
# FAIL (penalidade cheia da severidade) e WARN (metade). PASS/SKIP não punem.
# Porte de lib/scoring.mjs.

from typing import Any

from .models import CATEGORY, CATEGORY_ORDER, SEVERITY, STATUS, Finding


def verdict(score: int) -> dict[str, str]:
    if score >= 85:
        return {"key": "OK", "label": "Conforme"}
    if score >= 60:
        return {"key": "PARTIAL", "label": "Parcialmente conforme"}
    return {"key": "CRITICAL", "label": "Não conforme"}


def score(findings: list[Finding]) -> dict[str, Any]:
    by_category: dict[str, dict[str, Any]] = {}
    for key in CATEGORY_ORDER:
        by_category[key] = {
            "key": key,
            "label": CATEGORY[key].label,
            "short": CATEGORY[key].short,
            "penalty": 0.0,
            "findings": [],
            "counts": {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0},
        }

    for f in findings:
        cat = by_category.get(f.category)
        if not cat:
            continue
        cat["findings"].append(f)
        cat["counts"][f.status] = cat["counts"].get(f.status, 0) + 1
        w = SEVERITY[f.severity].weight if f.severity in SEVERITY else 0
        if f.status == STATUS.FAIL:
            cat["penalty"] += w
        elif f.status == STATUS.WARN:
            cat["penalty"] += w / 2

    categories = []
    for key in CATEGORY_ORDER:
        c = by_category[key]
        evaluated = c["counts"]["PASS"] + c["counts"]["FAIL"] + c["counts"]["WARN"]
        cat_score = None if evaluated == 0 else max(0, round(100 - c["penalty"]))
        categories.append({
            **c,
            "evaluated": evaluated,
            "score": cat_score,
            "verdict": None if cat_score is None else verdict(cat_score),
        })

    scored = [c for c in categories if c["score"] is not None]
    overall = round(sum(c["score"] for c in scored) / len(scored)) if scored else 0

    # Teto por severidade: uma vulnerabilidade confirmada (FAIL) crítica ou alta
    # não pode conviver com um score alto, mesmo que outras categorias passem.
    fail_orders = [SEVERITY[f.severity].order for f in findings if f.status == STATUS.FAIL]
    if fail_orders:
        worst_fail = min([99] + fail_orders)
        if worst_fail == SEVERITY["CRITICAL"].order:
            overall = min(overall, 50)
        elif worst_fail == SEVERITY["HIGH"].order:
            overall = min(overall, 70)

    totals = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    for f in findings:
        totals[f.status] = totals.get(f.status, 0) + 1

    return {"overall": overall, "verdict": verdict(overall), "categories": categories, "totals": totals}
