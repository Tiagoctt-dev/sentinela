# Autenticação e autorização do Sentinela (sem dependências extras):
#  - senhas com scrypt (salt por usuário);
#  - token assinado (HMAC-SHA256) com expiração;
#  - papéis: admin (tudo), analyst (roda scans e triagem), viewer (só leitura).
# SENTINELA_AUTH=off desliga a exigência de login (uso local/desenvolvimento).

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .db.models import UserModel
from .db.session import get_db
from .security import signing_key

TOKEN_TTL_S = 8 * 3600
ROLES = ("admin", "analyst", "viewer")
MIN_PASSWORD_LEN = 10


def auth_enabled() -> bool:
    return os.environ.get("SENTINELA_AUTH", "on").lower() not in ("off", "false", "0")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        candidate = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(candidate, _unb64(digest))
    except (ValueError, TypeError):
        return False


def make_token(user: UserModel) -> str:
    payload = _b64(json.dumps({"sub": user.id, "exp": int(time.time()) + TOKEN_TTL_S}).encode())
    sig = _b64(hmac.new(signing_key(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def _read_token(token: str) -> Optional[str]:
    try:
        payload, sig = token.split(".")
        expected = _b64(hmac.new(signing_key(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_unb64(payload))
        return data["sub"] if data["exp"] > time.time() else None
    except (ValueError, KeyError, TypeError):
        return None


class AnonymousAdmin:
    """Usado só com SENTINELA_AUTH=off."""

    id, email, name, role, active = "auth-off", "auth-off", "Modo local (sem login)", "admin", True


def user_from_request(request: Request, db: Session) -> Optional[UserModel]:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    uid = _read_token(header[7:].strip())
    if not uid:
        return None
    user = db.query(UserModel).filter(UserModel.id == uid).one_or_none()
    return user if user and user.active else None


def get_current_user(request: Request, db: Session = Depends(get_db)):
    if not auth_enabled():
        return AnonymousAdmin()
    user = user_from_request(request, db)
    if not user:
        raise HTTPException(401, "Sessão expirada ou inválida — entre novamente.")
    request.state.user_email = user.email
    return user


def guard(request: Request, user=Depends(get_current_user)):
    """Qualquer usuário logado lê; escrever exige analyst ou admin."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and user.role == "viewer":
        raise HTTPException(403, "Seu perfil é somente leitura.")
    return user


def admin_only(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Apenas administradores podem acessar esta área.")
    return user
