# Carregamento dos JSONs de alvo — sem dependência de banco/API, usado tanto
# pela CLI quanto pelas rotas.

import json
from pathlib import Path

TARGETS_DIR = Path(__file__).resolve().parent.parent / "targets"


class TargetNotFound(Exception):
    pass


def load_target_config(name: str) -> dict:
    path = TARGETS_DIR / f"{name}.json"
    if not path.exists():
        available = ", ".join(p.stem for p in TARGETS_DIR.glob("*.json"))
        raise TargetNotFound(f"Alvo não encontrado: {name}. Disponíveis: {available}")
    return json.loads(path.read_text(encoding="utf-8"))
