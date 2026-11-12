# Converte os achados em score por categoria e score geral.
#
# O score é um ÍNDICE DE CONFORMIDADE NAS VERIFICAÇÕES EXECUTADAS — não é uma
# garantia de segurança. Ele deve ser lido junto com a cobertura (scope.py).
#
# Modelo (documentado em docs/classificacao.md):
#   - cada categoria começa em 100;
#   - vulnerable + FAIL  : perde o peso cheio da severidade (crítico 40, alto 25, médio 15, baixo 7);
#   - vulnerable + WARN  : perde metade (alerta parcial);
#   - likely             : perde metade (indício, não prova);
#   - passed/inconclusive/error/not_run/not_applicable: não alteram o score
#     (mas "não executado" reduz a COBERTURA, informada à parte);
#   - teto: só uma falha CONFIRMADA crítica limita o score a 50 e uma alta, a 70.

from typing import Any

from .models import CATEGORY, CATEGORY_ORDER, SEVERITY, STATE, STATES, STATUS, Finding


def verdict(score: int) -> dict[str, str]:
    if score >= 85:
        return {"key": "OK", "label": "Conforme"}
    if score >= 60:
        return {"key": "PARTIAL", "label": "Parcialmente conforme"}
    return {"key": "CRITICAL", "label": "Não conforme"}


def penalty(f: Finding) -> float:
    w = SEVERITY[f.severity].weight if f.severity in SEVERITY else 0
    if f.state == STATE.VULNERABLE:
        return w if f.status == STATUS.FAIL else w / 2
    if f.state == STATE.LIKELY:
        return w / 2
    return 0.0


def score(findings: list[Finding]) -> dict[str, Any]:
    by_category: dict[str, dict[str, Any]] = {}
    for key in CATEGORY_ORDER:
        by_category[key] = {
            "key": key, "label": CATEGORY[key].label, "short": CATEGORY[key].short,
            "penalty": 0.0, "findings": [],
            "counts": {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0},
        }

    for f in findings:
        cat = by_category.get(f.category)
        if not cat:
            continue
        cat["findings"].append(f)
        cat["counts"][f.status] = cat["counts"].get(f.status, 0) + 1
        cat["penalty"] += penalty(f)

    categories = []
    for key in CATEGORY_ORDER:
        c = by_category[key]
        evaluated = c["counts"]["PASS"] + c["counts"]["FAIL"] + c["counts"]["WARN"]
        cat_score = None if evaluated == 0 else max(0, round(100 - c["penalty"]))
        categories.append({
            **c, "evaluated": evaluated, "score": cat_score,
            "verdict": None if cat_score is None else verdict(cat_score),
        })

    scored = [c for c in categories if c["score"] is not None]
    overall = round(sum(c["score"] for c in scored) / len(scored)) if scored else 0

    # Teto: somente falha CONFIRMADA (vulnerable + FAIL) limita o score.
    confirmed = [SEVERITY[f.severity].order for f in findings if f.state == STATE.VULNERABLE and f.status == STATUS.FAIL and f.severity in SEVERITY]
    if confirmed:
        worst = min(confirmed)
        if worst == SEVERITY["CRITICAL"].order:
            overall = min(overall, 50)
        elif worst == SEVERITY["HIGH"].order:
            overall = min(overall, 70)

    totals = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    states = {s: 0 for s in STATES}
    for f in findings:
        totals[f.status] = totals.get(f.status, 0) + 1
        states[f.state] = states.get(f.state, 0) + 1

    return {"overall": overall, "verdict": verdict(overall), "categories": categories, "totals": totals, "states": states}
