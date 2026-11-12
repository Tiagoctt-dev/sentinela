# Criptografia de segredos guardados no banco (credenciais de teste dos alvos).
# A chave vem de SENTINELA_SECRET_KEY; se não existir, é gerada uma vez em
# <SENTINELA_DATA_DIR>/.secret_key (por padrão, a pasta backend/, fora do git).
# Em produção/containers: defina a variável OU monte um volume em SENTINELA_DATA_DIR
# — sem isso, recriar o container gera outra chave e as credenciais guardadas ficam ilegíveis.

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _key_path() -> Path:
    data_dir = os.environ.get("SENTINELA_DATA_DIR")
    base = Path(data_dir) if data_dir else Path(__file__).resolve().parent.parent
    return base / ".secret_key"


_KEY_PATH = _key_path()  # mantido para compatibilidade; as funções abaixo recalculam via _key_path()


def _fernet() -> Fernet:
    env = os.environ.get("SENTINELA_SECRET_KEY")
    if env:
        return Fernet(env.encode())
    path = _key_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(Fernet.generate_key().decode(), encoding="utf-8")
        logger.warning("Chave de criptografia gerada em %s. Faça backup desse arquivo (ou defina SENTINELA_SECRET_KEY): "
                       "sem ela, credenciais de teste e segredos de integrações não podem ser lidos.", path)
    return Fernet(path.read_text(encoding="utf-8").strip().encode())


def encrypt(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as err:
        raise ValueError("Não foi possível descriptografar a credencial (chave SENTINELA_SECRET_KEY mudou?).") from err


def is_encrypted(value: str) -> bool:
    """Tokens Fernet começam com 'gAAAA' — usado para migrar segredos antigos em texto puro."""
    return bool(value) and value.startswith("gAAAA")


def mask_secret(value: str, keep: int = 4) -> str:
    return ("•" * 8 + value[-keep:]) if value and len(value) > keep else "•" * 8


def signing_key() -> bytes:
    """Chave para assinar tokens de sessão (derivada da mesma chave secreta)."""
    import hashlib

    _fernet()  # garante que a chave existe (cria backend/.secret_key na primeira vez)
    raw = os.environ.get("SENTINELA_SECRET_KEY") or _key_path().read_text(encoding="utf-8").strip()
    return hashlib.sha256(b"sentinela-session|" + raw.encode()).digest()


class SecretUnreadable(ValueError):
    """Segredo guardado que não pôde ser descriptografado (a chave mudou)."""


UNREADABLE_HINT = "ilegível — a chave de criptografia mudou; cadastre de novo"


def mask_encrypted(value: str, keep: int = 4) -> str:
    """Versão mascarada de um segredo guardado, sem nunca falhar (lista de integrações continua abrindo)."""
    try:
        return mask_secret(decrypt(value), keep)
    except ValueError:
        return UNREADABLE_HINT
