# Criptografia de segredos guardados no banco (credenciais de teste dos alvos).
# A chave vem de SENTINELA_SECRET_KEY; se não existir, é gerada uma vez em
# backend/.secret_key (fora do git). Em produção/containers, defina a variável.

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_PATH = Path(__file__).resolve().parent.parent / ".secret_key"


def _fernet() -> Fernet:
    env = os.environ.get("SENTINELA_SECRET_KEY")
    if env:
        return Fernet(env.encode())
    if not _KEY_PATH.exists():
        _KEY_PATH.write_text(Fernet.generate_key().decode(), encoding="utf-8")
    return Fernet(_KEY_PATH.read_text(encoding="utf-8").strip().encode())


def encrypt(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as err:
        raise ValueError("Não foi possível descriptografar a credencial (chave SENTINELA_SECRET_KEY mudou?).") from err


def signing_key() -> bytes:
    """Chave para assinar tokens de sessão (derivada da mesma chave secreta)."""
    import hashlib

    _fernet()  # garante que a chave existe (cria backend/.secret_key na primeira vez)
    raw = os.environ.get("SENTINELA_SECRET_KEY") or _KEY_PATH.read_text(encoding="utf-8").strip()
    return hashlib.sha256(b"sentinela-session|" + raw.encode()).digest()
