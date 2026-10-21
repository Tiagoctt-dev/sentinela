# Integrações: Webhook genérico, GitHub Issues e Slack.

from datetime import datetime, timezone
from typing import Optional

from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db.models import GithubIntegrationModel, SlackIntegrationModel, WebhookModel
from ..db.session import get_db

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def _validate_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or any(c.isspace() for c in url):
        raise HTTPException(400, "URL inválida — informe só o endereço que vai receber o evento, ex.: https://exemplo.com/webhook (sem espaços nem texto extra).")
    return url


def _serialize(w: WebhookModel) -> dict:
    return {
        "id": w.id, "name": w.name, "url": w.url, "enabled": w.enabled,
        "lastStatus": w.last_status,
        "lastTriggeredAt": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
        "createdAt": w.created_at.isoformat(),
    }


class WebhookCreate(BaseModel):
    name: str
    url: str


class WebhookUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("/webhooks")
def list_webhooks(db: Session = Depends(get_db)):
    rows = db.query(WebhookModel).order_by(WebhookModel.created_at).all()
    return [_serialize(w) for w in rows]


@router.post("/webhooks", status_code=201)
def create_webhook(body: WebhookCreate, db: Session = Depends(get_db)):
    w = WebhookModel(name=body.name, url=_validate_url(body.url), enabled=True)
    db.add(w)
    db.commit()
    db.refresh(w)
    return _serialize(w)


@router.put("/webhooks/{webhook_id}")
def update_webhook(webhook_id: str, body: WebhookUpdate, db: Session = Depends(get_db)):
    w = db.query(WebhookModel).filter(WebhookModel.id == webhook_id).one_or_none()
    if not w:
        raise HTTPException(404, "Webhook não encontrado")
    if body.name is not None:
        w.name = body.name
    if body.url is not None:
        w.url = _validate_url(body.url)
    if body.enabled is not None:
        w.enabled = body.enabled
    db.commit()
    db.refresh(w)
    return _serialize(w)


@router.delete("/webhooks/{webhook_id}", status_code=204)
def delete_webhook(webhook_id: str, db: Session = Depends(get_db)):
    w = db.query(WebhookModel).filter(WebhookModel.id == webhook_id).one_or_none()
    if not w:
        raise HTTPException(404, "Webhook não encontrado")
    db.delete(w)
    db.commit()


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str, db: Session = Depends(get_db)):
    w = db.query(WebhookModel).filter(WebhookModel.id == webhook_id).one_or_none()
    if not w:
        raise HTTPException(404, "Webhook não encontrado")
    payload = {"event": "webhook.test", "message": "Disparo de teste do Sentinela — se você recebeu isso, o webhook está funcionando."}
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(w.url, json=payload, timeout=6.0)
        w.last_status = f"HTTP {res.status_code}" if res.is_success else f"erro HTTP {res.status_code}"
    except Exception as err:  # noqa: BLE001
        w.last_status = f"falha: {err}"
    w.last_triggered_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(w)
    return _serialize(w)


# --- GitHub Issues ---------------------------------------------------------

def _serialize_github(g: GithubIntegrationModel) -> dict:
    masked = f"{'•' * max(len(g.token) - 4, 4)}{g.token[-4:]}" if g.token else ""
    return {
        "id": g.id, "repo": g.repo, "tokenMasked": masked, "enabled": g.enabled,
        "lastStatus": g.last_status,
        "lastTriggeredAt": g.last_triggered_at.isoformat() if g.last_triggered_at else None,
        "createdAt": g.created_at.isoformat(),
    }


class GithubIntegrationCreate(BaseModel):
    repo: str
    token: str


class GithubIntegrationUpdate(BaseModel):
    repo: Optional[str] = None
    token: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("/github")
def list_github(db: Session = Depends(get_db)):
    rows = db.query(GithubIntegrationModel).order_by(GithubIntegrationModel.created_at).all()
    return [_serialize_github(g) for g in rows]


@router.post("/github", status_code=201)
def create_github(body: GithubIntegrationCreate, db: Session = Depends(get_db)):
    if "/" not in body.repo:
        raise HTTPException(400, "Repositório inválido — use o formato owner/repo")
    g = GithubIntegrationModel(repo=body.repo, token=body.token, enabled=True)
    db.add(g)
    db.commit()
    db.refresh(g)
    return _serialize_github(g)


@router.put("/github/{integration_id}")
def update_github(integration_id: str, body: GithubIntegrationUpdate, db: Session = Depends(get_db)):
    g = db.query(GithubIntegrationModel).filter(GithubIntegrationModel.id == integration_id).one_or_none()
    if not g:
        raise HTTPException(404, "Integração não encontrada")
    if body.repo is not None:
        g.repo = body.repo
    if body.token is not None:
        g.token = body.token
    if body.enabled is not None:
        g.enabled = body.enabled
    db.commit()
    db.refresh(g)
    return _serialize_github(g)


@router.delete("/github/{integration_id}", status_code=204)
def delete_github(integration_id: str, db: Session = Depends(get_db)):
    g = db.query(GithubIntegrationModel).filter(GithubIntegrationModel.id == integration_id).one_or_none()
    if not g:
        raise HTTPException(404, "Integração não encontrada")
    db.delete(g)
    db.commit()


@router.post("/github/{integration_id}/test")
async def test_github(integration_id: str, db: Session = Depends(get_db)):
    g = db.query(GithubIntegrationModel).filter(GithubIntegrationModel.id == integration_id).one_or_none()
    if not g:
        raise HTTPException(404, "Integração não encontrada")
    headers = {"Authorization": f"Bearer {g.token}", "Accept": "application/vnd.github+json"}
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"https://api.github.com/repos/{g.repo}", headers=headers, timeout=6.0)
        if res.is_success:
            g.last_status = f"conectado a {g.repo}"
        elif res.status_code == 404:
            g.last_status = "erro: repositório não encontrado (ou token sem acesso)"
        elif res.status_code == 401:
            g.last_status = "erro: token inválido"
        else:
            g.last_status = f"erro HTTP {res.status_code}"
    except Exception as err:  # noqa: BLE001
        g.last_status = f"falha: {err}"
    g.last_triggered_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(g)
    return _serialize_github(g)


# --- Slack ------------------------------------------------------------------

def _serialize_slack(s: SlackIntegrationModel) -> dict:
    return {
        "id": s.id, "name": s.name, "webhookUrl": s.webhook_url, "enabled": s.enabled,
        "lastStatus": s.last_status,
        "lastTriggeredAt": s.last_triggered_at.isoformat() if s.last_triggered_at else None,
        "createdAt": s.created_at.isoformat(),
    }


class SlackIntegrationCreate(BaseModel):
    name: str
    webhookUrl: str


class SlackIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    webhookUrl: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("/slack")
def list_slack(db: Session = Depends(get_db)):
    rows = db.query(SlackIntegrationModel).order_by(SlackIntegrationModel.created_at).all()
    return [_serialize_slack(s) for s in rows]


@router.post("/slack", status_code=201)
def create_slack(body: SlackIntegrationCreate, db: Session = Depends(get_db)):
    if not body.webhookUrl.startswith("https://hooks.slack.com/"):
        raise HTTPException(400, "URL inválida — use a URL de Incoming Webhook gerada pelo Slack")
    s = SlackIntegrationModel(name=body.name, webhook_url=body.webhookUrl, enabled=True)
    db.add(s)
    db.commit()
    db.refresh(s)
    return _serialize_slack(s)


@router.put("/slack/{integration_id}")
def update_slack(integration_id: str, body: SlackIntegrationUpdate, db: Session = Depends(get_db)):
    s = db.query(SlackIntegrationModel).filter(SlackIntegrationModel.id == integration_id).one_or_none()
    if not s:
        raise HTTPException(404, "Integração não encontrada")
    if body.name is not None:
        s.name = body.name
    if body.webhookUrl is not None:
        s.webhook_url = body.webhookUrl
    if body.enabled is not None:
        s.enabled = body.enabled
    db.commit()
    db.refresh(s)
    return _serialize_slack(s)


@router.delete("/slack/{integration_id}", status_code=204)
def delete_slack(integration_id: str, db: Session = Depends(get_db)):
    s = db.query(SlackIntegrationModel).filter(SlackIntegrationModel.id == integration_id).one_or_none()
    if not s:
        raise HTTPException(404, "Integração não encontrada")
    db.delete(s)
    db.commit()


@router.post("/slack/{integration_id}/test")
async def test_slack(integration_id: str, db: Session = Depends(get_db)):
    s = db.query(SlackIntegrationModel).filter(SlackIntegrationModel.id == integration_id).one_or_none()
    if not s:
        raise HTTPException(404, "Integração não encontrada")
    payload = {"text": "🔧 Disparo de teste do Sentinela — se você recebeu isso no canal, a integração com o Slack está funcionando."}
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(s.webhook_url, json=payload, timeout=6.0)
        s.last_status = f"HTTP {res.status_code}" if res.is_success else f"erro HTTP {res.status_code}"
    except Exception as err:  # noqa: BLE001
        s.last_status = f"falha: {err}"
    s.last_triggered_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(s)
    return _serialize_slack(s)
