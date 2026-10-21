# Login, primeiro acesso (bootstrap do administrador), gestão de usuários e
# trilha de auditoria.

import re
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import (MIN_PASSWORD_LEN, ROLES, admin_only, auth_enabled, get_current_user, hash_password,
                    make_token, verify_password)
from ..db.models import AuditLogModel, UserModel
from ..db.session import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"], dependencies=[Depends(admin_only)])
audit_router = APIRouter(prefix="/api/audit", tags=["audit"], dependencies=[Depends(admin_only)])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_failures: dict[str, list[float]] = {}
MAX_FAILURES, WINDOW_S = 5, 300
_DUMMY_HASH = hash_password("dummy-password-for-timing")


def _serialize(u: UserModel) -> dict:
    return {
        "id": u.id, "email": u.email, "name": u.name, "role": u.role, "active": u.active,
        "createdAt": u.created_at.isoformat(), "lastLoginAt": u.last_login_at.isoformat() if u.last_login_at else None,
    }


def _check_password_rules(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise HTTPException(400, f"A senha precisa ter pelo menos {MIN_PASSWORD_LEN} caracteres.")


def _check_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "E-mail inválido.")
    return email


class SetupBody(BaseModel):
    name: str
    email: str
    password: str


class LoginBody(BaseModel):
    email: str
    password: str


@router.get("/status")
def status(db: Session = Depends(get_db)):
    return {"authRequired": auth_enabled(), "hasUsers": db.query(UserModel).count() > 0}


@router.post("/bootstrap", status_code=201)
def bootstrap(body: SetupBody, db: Session = Depends(get_db)):
    if db.query(UserModel).count() > 0:
        raise HTTPException(409, "O administrador inicial já foi criado.")
    _check_password_rules(body.password)
    user = UserModel(name=body.name.strip(), email=_check_email(body.email), password_hash=hash_password(body.password), role="admin",
                     last_login_at=datetime.now(timezone.utc))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"token": make_token(user), "user": _serialize(user)}


@router.post("/login")
def login(body: LoginBody, request: Request, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    key = f"{email}|{request.client.host if request.client else ''}"
    now = time.time()
    recent = [t for t in _failures.get(key, []) if now - t < WINDOW_S]
    if len(recent) >= MAX_FAILURES:
        raise HTTPException(429, "Muitas tentativas. Aguarde alguns minutos e tente de novo.")

    user = db.query(UserModel).filter(UserModel.email == email).one_or_none()
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)  # mesmo custo com ou sem usuário
    if not user or not ok or not user.active:
        _failures[key] = recent + [now]
        raise HTTPException(401, "E-mail ou senha incorretos.")

    _failures.pop(key, None)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return {"token": make_token(user), "user": _serialize(user)}


@router.get("/me")
def me(user=Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role}


# ---------------- usuários (admin) ----------------
class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str = "analyst"


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


def _admins_left(db: Session, excluding: str) -> int:
    return db.query(UserModel).filter(UserModel.role == "admin", UserModel.active.is_(True), UserModel.id != excluding).count()


@users_router.get("")
def list_users(db: Session = Depends(get_db)):
    return [_serialize(u) for u in db.query(UserModel).order_by(UserModel.created_at).all()]


@users_router.post("", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db)):
    if body.role not in ROLES:
        raise HTTPException(400, f"Papel inválido — use um de: {', '.join(ROLES)}.")
    _check_password_rules(body.password)
    email = _check_email(body.email)
    if db.query(UserModel).filter(UserModel.email == email).first():
        raise HTTPException(409, "Já existe um usuário com esse e-mail.")
    u = UserModel(name=body.name.strip(), email=email, password_hash=hash_password(body.password), role=body.role)
    db.add(u)
    db.commit()
    db.refresh(u)
    return _serialize(u)


@users_router.put("/{user_id}")
def update_user(user_id: str, body: UserUpdate, db: Session = Depends(get_db), me=Depends(get_current_user)):
    u = db.query(UserModel).filter(UserModel.id == user_id).one_or_none()
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(400, f"Papel inválido — use um de: {', '.join(ROLES)}.")
        if u.role == "admin" and body.role != "admin" and _admins_left(db, u.id) == 0:
            raise HTTPException(400, "Não é possível remover o último administrador.")
        u.role = body.role
    if body.active is not None:
        if not body.active and (u.id == me.id or (u.role == "admin" and _admins_left(db, u.id) == 0)):
            raise HTTPException(400, "Não é possível desativar a si mesmo nem o último administrador.")
        u.active = body.active
    if body.name is not None:
        u.name = body.name.strip()
    if body.password:
        _check_password_rules(body.password)
        u.password_hash = hash_password(body.password)
    db.commit()
    db.refresh(u)
    return _serialize(u)


@users_router.delete("/{user_id}", status_code=204)
def delete_user(user_id: str, db: Session = Depends(get_db), me=Depends(get_current_user)):
    u = db.query(UserModel).filter(UserModel.id == user_id).one_or_none()
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    if u.id == me.id or (u.role == "admin" and _admins_left(db, u.id) == 0):
        raise HTTPException(400, "Não é possível excluir a si mesmo nem o último administrador.")
    db.delete(u)
    db.commit()


# ---------------- auditoria (admin) ----------------
@audit_router.get("")
def list_audit(db: Session = Depends(get_db), limit: int = 200):
    rows = db.query(AuditLogModel).order_by(AuditLogModel.created_at.desc()).limit(min(limit, 1000)).all()
    return [
        {"id": r.id, "user": r.user_email, "method": r.method, "path": r.path, "status": r.status_code,
         "ip": r.ip, "createdAt": r.created_at.isoformat()}
        for r in rows
    ]
