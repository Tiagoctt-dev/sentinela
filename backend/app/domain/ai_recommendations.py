# Orquestra a camada de IA Generativa: roda os provedores configurados
# (Gemini e Groq) EM PARALELO sobre o mesmo prompt, pra ter duas "opiniões"
# independentes sobre os mesmos achados — cada achado fica com uma
# recomendação por provedor. Sempre degrada com elegância: sem nenhuma chave
# configurada, ou se um provedor falhar, o scanner segue com o que sobrar
# (ou com as recomendações estáticas, se nenhum provedor responder).

import asyncio
import logging
import os
from typing import Any, Callable

import httpx

from .ai_prompt import build_prompt, parse_json
from .ai_providers import TransientAIError, call_gemini, call_groq
from .models import STATUS, Finding

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 3


def _gemini_models() -> list[str]:
    configured = os.environ.get("GEMINI_MODEL")
    # "-latest" é um alias móvel que fica sobrecarregado com frequência (503) — vai por último.
    return [configured] if configured else ["gemini-2.5-flash", "gemini-3.5-flash", "gemini-flash-latest"]


def _groq_models() -> list[str]:
    configured = os.environ.get("GROQ_MODEL")
    return [configured] if configured else ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]


PROVIDERS: list[dict[str, Any]] = [
    {"key": "gemini", "label": "Gemini", "env_key": "GEMINI_API_KEY", "models": _gemini_models, "call": call_gemini},
    {"key": "groq", "label": "Groq", "env_key": "GROQ_API_KEY", "models": _groq_models, "call": call_groq},
]


async def call_with_fallback(provider: dict[str, Any], client: httpx.AsyncClient, api_key: str, prompt: str) -> tuple[str | None, str | None, Exception | None]:
    """Tenta cada modelo do provedor (com retry/backoff em erros temporários).
    Devolve (texto, modelo_usado, último_erro)."""
    call: Callable = provider["call"]
    last_err: Exception | None = None
    for model in provider["models"]():
        for attempt in range(MAX_ATTEMPTS):
            try:
                return await call(client, api_key, model, prompt), model, None
            except TransientAIError as err:
                logger.warning("Falha temporária em %s (model=%s, tentativa %d/%d): %s", provider["label"], model, attempt + 1, MAX_ATTEMPTS, err)
                last_err = err
                if attempt < MAX_ATTEMPTS - 1:
                    await asyncio.sleep(1.5 * (attempt + 1))
            except Exception as err:  # noqa: BLE001 — erro permanente: não adianta repetir, vai pro próximo modelo
                logger.warning("Falha ao chamar %s (model=%s): %s", provider["label"], model, err)
                last_err = err
                break
    return None, None, last_err


async def _run_provider(provider: dict[str, Any], client: httpx.AsyncClient, prompt: str) -> dict[str, Any]:
    api_key = os.environ.get(provider["env_key"])
    if not api_key:
        return {
            "provider": provider["label"], "key": provider["key"], "enabled": False,
            "reason": f"{provider['env_key']} não configurada (crie backend/.env).",
        }

    text, used_model, last_err = await call_with_fallback(provider, client, api_key, prompt)

    if text is None:
        return {
            "provider": provider["label"], "key": provider["key"], "enabled": False,
            "reason": f"Falha ao chamar a IA ({last_err}).",
        }

    try:
        parsed = parse_json(text)
    except Exception as err:  # noqa: BLE001
        return {
            "provider": provider["label"], "key": provider["key"], "enabled": False, "model": used_model,
            "reason": f"Resposta em formato inesperado ({err}).",
        }

    recs = {r["id"]: r for r in parsed.get("recomendacoes", []) if r.get("id")}
    return {
        "provider": provider["label"], "key": provider["key"], "enabled": True, "model": used_model,
        "summary": parsed.get("resumoExecutivo", ""), "count": len(recs), "recs": recs,
    }


def _disabled_reason(disabled_msg: str) -> list[dict[str, Any]]:
    return [{"provider": p["label"], "key": p["key"], "enabled": False, "reason": disabled_msg} for p in PROVIDERS]


async def enrich_with_ai(target: dict, result: dict, findings: list[Finding], disabled: bool = False) -> list[dict[str, Any]]:
    if disabled:
        return _disabled_reason("desativado por --no-ai")

    configured = [p for p in PROVIDERS if os.environ.get(p["env_key"])]
    if not configured:
        return _disabled_reason("Nenhuma chave de IA configurada (GEMINI_API_KEY / GROQ_API_KEY em backend/.env). Usando recomendações estáticas.")

    actionable = [f for f in findings if f.status in (STATUS.FAIL, STATUS.WARN)]
    if not actionable:
        return [
            {"provider": p["label"], "key": p["key"], "enabled": True,
             "summary": "Nenhum achado crítico: a API atende às práticas verificadas."}
            for p in configured
        ]

    prompt = build_prompt(target, result, actionable)
    async with httpx.AsyncClient() as client:
        outcomes = await asyncio.gather(*[_run_provider(p, client, prompt) for p in PROVIDERS])

    # Mescla as recomendações de cada provedor no achado — "duas visões" lado a lado.
    for f in findings:
        merged: dict[str, Any] = {}
        for o in outcomes:
            r = (o.get("recs") or {}).get(f.id)
            if r:
                merged[o["key"]] = {
                    "provider": o["provider"], "prioridade": r.get("prioridade"),
                    "risco": r.get("risco"), "acao": r.get("acao"),
                }
        f.ai_rec = merged or None

    return [{k: v for k, v in o.items() if k != "recs"} for o in outcomes]
