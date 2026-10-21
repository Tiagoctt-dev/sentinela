# Chamadas HTTP de baixo nível pra cada provedor de IA. Cada uma recebe o
# mesmo prompt e devolve o texto bruto da resposta (ou levanta RuntimeError).
# O orquestrador (ai_recommendations.py) decide quais provedores rodar e como
# degradar se um deles falhar.

import os

import httpx


class TransientAIError(RuntimeError):
    """Erro temporário (sobrecarga/limite/timeout) — vale tentar de novo antes de trocar de modelo."""


def _raise_for_status(status: int, text: str) -> None:
    if status in (500, 502, 503, 504, 429):
        raise TransientAIError(f"HTTP {status} (sobrecarga temporária do provedor)")
    if status in (401, 403):
        raise RuntimeError(f"HTTP {status} (chave de API inválida ou sem permissão) {text[:160]}")
    if status == 404:
        raise RuntimeError(f"HTTP {status} (modelo inexistente/indisponível) {text[:160]}")
    if status >= 400:
        raise RuntimeError(f"HTTP {status} {text[:160]}")


async def call_gemini(client: httpx.AsyncClient, api_key: str, model: str, prompt: str) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json", "temperature": 0.3},
    }
    timeout_s = float(os.environ.get("AI_TIMEOUT_MS", "25000")) / 1000
    try:
        res = await client.post(url, json=body, headers={"x-goog-api-key": api_key}, timeout=timeout_s)
    except httpx.TimeoutException as err:
        raise TransientAIError(f"timeout após {timeout_s:.0f}s") from err
    except Exception as err:  # noqa: BLE001
        raise RuntimeError(str(err)) from err

    if res.is_error:
        _raise_for_status(res.status_code, res.text)

    data = res.json()
    parts = (((data.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts)


async def call_groq(client: httpx.AsyncClient, api_key: str, model: str, prompt: str) -> str:
    # API compatível com OpenAI — https://console.groq.com/docs/api-reference
    url = "https://api.groq.com/openai/v1/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "response_format": {"type": "json_object"},
    }
    timeout_s = float(os.environ.get("AI_TIMEOUT_MS", "25000")) / 1000
    try:
        res = await client.post(url, json=body, headers={"Authorization": f"Bearer {api_key}"}, timeout=timeout_s)
    except httpx.TimeoutException as err:
        raise TransientAIError(f"timeout após {timeout_s:.0f}s") from err
    except Exception as err:  # noqa: BLE001
        raise RuntimeError(str(err)) from err

    if res.is_error:
        _raise_for_status(res.status_code, res.text)

    data = res.json()
    choices = data.get("choices") or []
    return (choices[0].get("message", {}).get("content", "") if choices else "")
