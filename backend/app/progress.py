# Progresso dos scans em andamento (em memória, por processo): o front consulta enquanto a requisição do scan
# ainda está aberta. Só guarda etapa atual e contagem; nada sensível.

import threading
import time

_lock = threading.Lock()
_state: dict[str, dict] = {}


def start(key: str, total: int) -> None:
    with _lock:
        _state[key] = {"targetId": key, "label": "Preparando", "done": 0, "total": max(1, total), "startedAt": time.time()}


def step(key: str, label: str) -> None:
    """Marca o início da etapa `label`; a etapa anterior passa a contar como concluída."""
    with _lock:
        st = _state.get(key)
        if st:
            if st["label"] != "Preparando":
                st["done"] = min(st["done"] + 1, st["total"])
            st["label"] = label


def finish(key: str) -> None:
    with _lock:
        _state.pop(key, None)


def running() -> list[dict]:
    with _lock:
        return [dict(v) for v in _state.values()]
