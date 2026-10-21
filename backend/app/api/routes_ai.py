# Diagnóstico da camada de IA: testa de verdade cada provedor configurado e
# devolve o motivo real da falha (sem nunca expor a chave).

import os
import time

import httpx
from fastapi import APIRouter

from ..domain.ai_recommendations import PROVIDERS, call_with_fallback

router = APIRouter(prefix="/api/ai", tags=["ai"])


def _hint(key: str) -> str:
    return f"…{key[-4:]}" if len(key) > 8 else "…"


@router.post("/test")
async def test_ai():
    results = []
    async with httpx.AsyncClient() as client:
        for p in PROVIDERS:
            key = os.environ.get(p["env_key"])
            if not key:
                results.append({
                    "provider": p["label"], "configured": False, "ok": False,
                    "message": f"{p['env_key']} não configurada em backend/.env.",
                })
                continue
            started = time.monotonic()
            text, model, err = await call_with_fallback(p, client, key, 'Responda somente com o JSON {"ok": true}')
            elapsed_ms = round((time.monotonic() - started) * 1000)
            if text is not None:
                results.append({
                    "provider": p["label"], "configured": True, "ok": True, "model": model,
                    "latencyMs": elapsed_ms, "keyHint": _hint(key),
                    "message": f"Respondeu em {elapsed_ms} ms usando {model}.",
                })
            else:
                results.append({
                    "provider": p["label"], "configured": True, "ok": False, "keyHint": _hint(key),
                    "latencyMs": elapsed_ms, "message": str(err),
                    "transient": "sobrecarga" in str(err) or "timeout" in str(err),
                })
    return results
