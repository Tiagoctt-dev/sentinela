# Canário de SSRF: o Sentinela hospeda uma URL única; se o alvo fizer uma
# requisição a ela depois de receber essa URL num parâmetro, a SSRF está
# confirmada (funciona mesmo quando a resposta não volta ao atacante).

import os
import uuid
from collections import OrderedDict

MAX_TOKENS = 5000
_issued: "OrderedDict[str, bool]" = OrderedDict()


def public_base() -> str:
    return os.environ.get("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")


def new_token() -> str:
    token = uuid.uuid4().hex
    _issued[token] = False
    while len(_issued) > MAX_TOKENS:
        _issued.popitem(last=False)
    return token


def url_for(token: str) -> str:
    return f"{public_base()}/api/canary/{token}"


def record(token: str) -> None:
    """Só registra tokens emitidos pelo Sentinela (impede encher a memória com tokens arbitrários)."""
    if token in _issued:
        _issued[token] = True


def was_hit(token: str) -> bool:
    return _issued.get(token, False)
