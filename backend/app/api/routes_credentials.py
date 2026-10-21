# Credenciais de teste por alvo (usuários com papéis diferentes, usados pelos
# testes autenticados: BOLA, BFLA, JWT...). A senha é criptografada e nunca
# volta pela API — só "passwordSet".

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.models import CredentialModel, TargetModel
from ..db.session import get_db
from ..security import decrypt, encrypt

router = APIRouter(prefix="/api/targets/{target_id}/credentials", tags=["credentials"])


def _serialize(c: CredentialModel) -> dict:
    return {
        "id": c.id, "label": c.label, "role": c.role, "username": c.username,
        "resourceId": c.resource_id, "passwordSet": True, "createdAt": c.created_at.isoformat(),
    }


class CredentialCreate(BaseModel):
    label: str
    role: str = "user"
    username: str
    password: str
    resourceId: Optional[str] = None


class CredentialUpdate(BaseModel):
    label: Optional[str] = None
    role: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    resourceId: Optional[str] = None


def _target(db: Session, target_id: str) -> TargetModel:
    t = db.query(TargetModel).filter(TargetModel.id == target_id).one_or_none()
    if not t:
        raise HTTPException(404, "Alvo não encontrado")
    return t


def _get(db: Session, target_id: str, cred_id: str) -> CredentialModel:
    c = db.query(CredentialModel).filter(CredentialModel.id == cred_id, CredentialModel.target_id == target_id).one_or_none()
    if not c:
        raise HTTPException(404, "Credencial não encontrada")
    return c


def load_credentials(db: Session, target_id: str) -> list[dict]:
    """Uso interno do scan: credenciais em claro, só em memória."""
    rows = db.query(CredentialModel).filter(CredentialModel.target_id == target_id).order_by(CredentialModel.created_at).all()
    return [
        {"label": c.label, "role": c.role, "username": c.username, "password": decrypt(c.password_enc), "resourceId": c.resource_id}
        for c in rows
    ]


@router.get("")
def list_credentials(target_id: str, db: Session = Depends(get_db)):
    _target(db, target_id)
    rows = db.query(CredentialModel).filter(CredentialModel.target_id == target_id).order_by(CredentialModel.created_at).all()
    return [_serialize(c) for c in rows]


@router.post("", status_code=201)
def create_credential(target_id: str, body: CredentialCreate, db: Session = Depends(get_db)):
    _target(db, target_id)
    c = CredentialModel(
        target_id=target_id, label=body.label.strip(), role=body.role.strip() or "user",
        username=body.username.strip(), password_enc=encrypt(body.password), resource_id=(body.resourceId or None),
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return _serialize(c)


@router.put("/{cred_id}")
def update_credential(target_id: str, cred_id: str, body: CredentialUpdate, db: Session = Depends(get_db)):
    c = _get(db, target_id, cred_id)
    if body.label is not None:
        c.label = body.label.strip()
    if body.role is not None:
        c.role = body.role.strip() or "user"
    if body.username is not None:
        c.username = body.username.strip()
    if body.password:
        c.password_enc = encrypt(body.password)
    if body.resourceId is not None:
        c.resource_id = body.resourceId or None
    db.commit()
    db.refresh(c)
    return _serialize(c)


@router.delete("/{cred_id}", status_code=204)
def delete_credential(target_id: str, cred_id: str, db: Session = Depends(get_db)):
    c = _get(db, target_id, cred_id)
    db.delete(c)
    db.commit()
