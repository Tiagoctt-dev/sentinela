# Canário de SSRF: o Sentinela hospeda uma URL única; se o alvo fizer uma
# requisição a ela depois de receber essa URL num parâmetro, a SSRF está
# confirmada (funciona mesmo quando a resposta não volta ao atacante).

import os
import uuid

_hits: set[str] = set()


def public_base() -> str:
    return os.environ.get("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")


def new_token() -> str:
    return uuid.uuid4().hex


def url_for(token: str) -> str:
    return f"{public_base()}/api/canary/{token}"


def record(token: str) -> None:
    _hits.add(token)


def was_hit(token: str) -> bool:
    return token in _hits
