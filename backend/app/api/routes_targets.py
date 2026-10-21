import uuid
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.models import TargetModel
from ..db.session import SessionLocal, get_db
from ..targets import TARGETS_DIR, TargetNotFound, load_target_config as _load_target_config

router = APIRouter(prefix="/api/targets", tags=["targets"])


def load_target_config(name: str) -> dict:
    try:
        return _load_target_config(name)
    except TargetNotFound as err:
        raise HTTPException(404, str(err)) from err


def seed_file_targets() -> None:
    # Roda no startup: garante que os alvos de exemplo (targets/*.json) têm um
    # registro estável no banco (id fixo), sincronizando a config a cada boot
    # — o arquivo é sempre a fonte da verdade para esses.
    db = SessionLocal()
    try:
        for path in TARGETS_DIR.glob("*.json"):
            name = path.stem
            config = _load_target_config(name)
            existing = db.query(TargetModel).filter(TargetModel.name == name).one_or_none()
            if existing:
                existing.source = "file"
                if existing.config != config:
                    existing.config = config
            else:
                db.add(TargetModel(name=name, source="file", config=config))
        db.commit()
    finally:
        db.close()


def get_or_create_target(db: Session, name: str) -> TargetModel:
    """Compat: resolve um alvo pelo nome do arquivo (usado pela CLI)."""
    config = load_target_config(name)
    existing = db.query(TargetModel).filter(TargetModel.name == name).one_or_none()
    if existing:
        if existing.config != config:
            existing.config = config
            db.commit()
            db.refresh(existing)
        return existing
    t = TargetModel(name=name, source="file", config=config)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def get_or_create_url_target(db: Session, url: str) -> TargetModel:
    """Scan avulso: cadastra (ou reaproveita) um alvo custom a partir de uma
    URL, sem precisar preencher um formulário antes — mas já fica no CRUD."""
    normalized = url.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "URL inválida — inclua o protocolo, ex.: https://exemplo.com")

    custom = db.query(TargetModel).filter(TargetModel.source == "custom").all()
    existing = next((t for t in custom if t.config.get("baseUrl") == normalized), None)
    if existing:
        return existing

    config = {"name": parsed.netloc, "description": "", "baseUrl": normalized, "endpoints": {}}
    t = TargetModel(name=f"url:{normalized}", source="custom", config=config)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _serialize(t: TargetModel) -> dict:
    return {"id": t.id, "name": t.name, "source": t.source, "config": t.config, "createdAt": t.created_at.isoformat()}


class TargetCreate(BaseModel):
    name: str
    baseUrl: str
    description: Optional[str] = ""
    endpoints: Optional[dict] = None
    auth: Optional[dict] = None
    bola: Optional[dict] = None
    massAssignment: Optional[dict] = None
    bfla: Optional[list] = None
    openapiUrl: Optional[str] = None
    wsdlUrl: Optional[str] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    baseUrl: Optional[str] = None
    description: Optional[str] = None
    endpoints: Optional[dict] = None
    auth: Optional[dict] = None
    bola: Optional[dict] = None
    massAssignment: Optional[dict] = None
    bfla: Optional[list] = None
    openapiUrl: Optional[str] = None
    wsdlUrl: Optional[str] = None


def _build_config(body: TargetCreate) -> dict:
    parsed = urlparse(body.baseUrl.rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "baseUrl inválida — inclua o protocolo, ex.: https://exemplo.com")
    config: dict = {"name": body.name, "description": body.description or "", "baseUrl": body.baseUrl.rstrip("/")}
    if body.endpoints:
        config["endpoints"] = body.endpoints
    if body.auth:
        config["auth"] = body.auth
    if body.bola:
        config["bola"] = body.bola
    if body.massAssignment:
        config["massAssignment"] = body.massAssignment
    if body.bfla:
        config["bfla"] = body.bfla
    if body.openapiUrl:
        config["openapiUrl"] = body.openapiUrl.strip()
    if body.wsdlUrl:
        config["wsdlUrl"] = body.wsdlUrl.strip()
    return config


@router.get("")
def list_targets(db: Session = Depends(get_db)):
    rows = db.query(TargetModel).order_by(TargetModel.source.desc(), TargetModel.created_at).all()
    return [_serialize(t) for t in rows]


@router.post("", status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db)):
    # `name` (coluna interna, única) é só um identificador opaco — o nome
    # digitado pelo usuário vive em config["name"] e pode se repetir à vontade.
    t = TargetModel(name=f"custom:{uuid.uuid4()}", source="custom", config=_build_config(body))
    db.add(t)
    db.commit()
    db.refresh(t)
    return _serialize(t)


@router.get("/{target_id}")
def get_target(target_id: str, db: Session = Depends(get_db)):
    t = db.query(TargetModel).filter(TargetModel.id == target_id).one_or_none()
    if not t:
        raise HTTPException(404, "Alvo não encontrado")
    return _serialize(t)


@router.put("/{target_id}")
def update_target(target_id: str, body: TargetUpdate, db: Session = Depends(get_db)):
    t = db.query(TargetModel).filter(TargetModel.id == target_id).one_or_none()
    if not t:
        raise HTTPException(404, "Alvo não encontrado")
    if t.source == "file":
        raise HTTPException(400, "Este é um alvo de exemplo (targets/*.json) — edite o arquivo em vez da API.")

    config = dict(t.config)
    if body.name is not None:
        config["name"] = body.name
    if body.description is not None:
        config["description"] = body.description
    if body.baseUrl is not None:
        parsed = urlparse(body.baseUrl.rstrip("/"))
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise HTTPException(400, "baseUrl inválida — inclua o protocolo, ex.: https://exemplo.com")
        config["baseUrl"] = body.baseUrl.rstrip("/")
    if body.endpoints is not None:
        config["endpoints"] = body.endpoints
    if body.auth is not None:
        config["auth"] = body.auth
    if body.bola is not None:
        config["bola"] = body.bola
    if body.massAssignment is not None:
        config["massAssignment"] = body.massAssignment
    if body.bfla is not None:
        config["bfla"] = body.bfla
    if body.openapiUrl is not None:
        config["openapiUrl"] = body.openapiUrl.strip()
    if body.wsdlUrl is not None:
        config["wsdlUrl"] = body.wsdlUrl.strip()

    t.config = config
    db.commit()
    db.refresh(t)
    return _serialize(t)


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: str, db: Session = Depends(get_db)):
    t = db.query(TargetModel).filter(TargetModel.id == target_id).one_or_none()
    if not t:
        raise HTTPException(404, "Alvo não encontrado")
    if t.source == "file":
        raise HTTPException(400, "Este é um alvo de exemplo (targets/*.json) — não pode ser excluído pela API.")
    db.delete(t)
    db.commit()
