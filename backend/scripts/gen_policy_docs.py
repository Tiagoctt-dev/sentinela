"""Gera docs/politicas.md a partir do catálogo e da base editorial — a documentação nunca diverge do código.
Cada política é ligada aos testes automatizados que a mencionam (pelo id no nome ou no corpo do teste).

Uso (na pasta backend):  .venv/Scripts/python scripts/gen_policy_docs.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.api.routes_policies import COVERAGE  # noqa: E402
from app.domain.knowledge import cwe_ref, knowledge_for, owasp_ref  # noqa: E402
from app.domain.owasp_api_top10 import OWASP_API_TOP10  # noqa: E402
from app.domain.policy_catalog import CHECKS, NEEDS_CONFIG  # noqa: E402

PROOF = {"confirmed": "prova direta", "indicative": "indício"}
COV = {"coberto": "cobertura ampla", "parcial": "cobertura parcial", "nao_coberto": "sem verificação"}


ALIASES = {"D-AUTHZ-0N": ("D-AUTHZ-0",), "D-BFLA-0N": ("D-BFLA-0",)}


def _mentions(cid: str, text: str) -> bool:
    return cid in text or cid.replace("-", "_") in text or any(a in text for a in ALIASES.get(cid, ()))


def tests_by_check() -> dict[str, list[str]]:
    """Liga cada política aos testes que a mencionam no nome, no corpo, no decorador ou em listas
    de parâmetros (ex.: @pytest.mark.parametrize("check", NEXT_RULES))."""
    found: dict[str, list[str]] = {c["id"]: [] for c in CHECKS}
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        constants = dict(re.findall(r"(?ms)^([A-Z][A-Z_]+)\s*=\s*(\[.*?\])\s*$", text))
        pieces = re.split(r"(?m)^(?:async )?def (test_\w+)", text)
        for i in range(1, len(pieces), 2):
            name, body = pieces[i], pieces[i + 1]
            decorators = " ".join(pieces[i - 1].splitlines()[-12:])  # linhas logo acima do def
            extra = " ".join(constants.get(n, "") for n in re.findall(r"[A-Z][A-Z_]{3,}", decorators))
            haystack = f"{name} {body} {decorators} {extra}"
            for cid in found:
                if _mentions(cid, haystack):
                    found[cid].append(f"{path.name}::{name}")
    return found


def main() -> None:
    tests = tests_by_check()
    lines = [
        "# Catálogo de políticas",
        "",
        "> Gerado por `backend/scripts/gen_policy_docs.py` a partir de `policy_catalog.py` e `knowledge.py`. Não edite à mão: altere o código e gere de novo.",
        "",
        "Cada **política** é uma verificação com critérios explícitos. O resultado de cada uma é descrito por três eixos independentes",
        "(ver [classificacao.md](classificacao.md)): **severidade** (impacto potencial), **confiança** (o quanto a verificação prova) e **estado** (o que aconteceu).",
        "",
        "## Cobertura declarada do OWASP API Security Top 10 (2023)",
        "",
        "| Item | Cobertura | Limites |",
        "|---|---|---|",
    ]
    for o in OWASP_API_TOP10:
        level, note = COVERAGE[o["id"]]
        lines.append(f"| [{o['id']} — {o['nome']}]({owasp_ref(o['id'])['url']}) | {COV[level]} | {note} |")
    lines += ["", "Nenhum item é marcado como coberto só por existir uma política com o nome correspondente.", ""]

    for o in OWASP_API_TOP10:
        checks = [c for c in CHECKS if c["owasp"] == o["id"]]
        lines += [f"## {o['id']} — {o['nome']}", "", o["desc"], ""]
        if not checks:
            lines += ["_Nenhuma política implementada para este item._", ""]
            continue
        for c in checks:
            k = knowledge_for(c["id"]) or {}
            refs = ", ".join(f"[{r['label']}]({r['url']})" for r in ([owasp_ref(c["owasp"])] if owasp_ref(c["owasp"]) else []) + [cwe_ref(n) for n in k.get("cwe", [])])
            lines += [
                f"### `{c['id']}` — {c['title']}",
                "",
                f"- **Tipo:** {'análise de código' if c['kind'] == 'static' else 'teste ao vivo'} · **Severidade:** {c['severity']} · **Prova:** {PROOF.get(k.get('proof'), '—')}"
                + (" · **Requer configuração do projeto**" if c["id"] in NEEDS_CONFIG else ""),
                f"- **Objetivo:** {k.get('objective', '—')}",
                f"- **Como testa:** {c['how']}",
                f"- **Pré-requisitos:** {k.get('prerequisites', '—')}",
                f"- **Aprova quando:** {k.get('passWhen', '—')}",
                f"- **Reprova quando:** {k.get('failWhen', '—')}",
                f"- **Cenário de exploração:** {k.get('exploitation', '—')}",
                f"- **Impacto:** {k.get('impact', '—')}",
                f"- **Por que esta severidade:** {k.get('severityReason', '—')}",
                f"- **Limitações:** {k.get('limitations', '—')}",
                f"- **Referências:** {refs or '—'}",
                "- **Testes automatizados:** " + (", ".join(f"`{t}`" for t in tests[c["id"]]) if tests[c["id"]] else "_nenhum teste dedicado — coberta apenas pelos testes gerais do pipeline_"),
                "",
            ]
    out = ROOT.parent / "docs" / "politicas.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    sem_teste = [cid for cid, t in tests.items() if not t]
    print(f"docs/politicas.md gerado: {len(CHECKS)} políticas; sem teste dedicado: {len(sem_teste)} -> {sem_teste}")


if __name__ == "__main__":
    main()
