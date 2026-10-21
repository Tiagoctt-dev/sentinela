# Endpoint-canário do teste de SSRF: registra que alguém (o alvo) o acessou.

from fastapi import APIRouter

from ..domain import canary

router = APIRouter(prefix="/api/canary", tags=["canary"])


@router.api_route("/{token}", methods=["GET", "POST", "PUT", "HEAD"])
def hit(token: str):
    canary.record(token)
    return {"ok": True}
