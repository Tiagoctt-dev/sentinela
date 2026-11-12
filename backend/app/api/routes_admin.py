# Administração: política de retenção de dados e métricas operacionais.

import hmac
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import metrics
from ..auth import admin_only, auth_enabled, user_from_request
from ..db.models import AuditLogModel, FindingModel, ScanRun
from ..db.session import get_db
from ..retention import policy, purge
from ..domain.triage import expire_risk_acceptances

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(admin_only)])
metrics_router = APIRouter(prefix="/api", tags=["metrics"])


@router.get("/retention")
def retention_status(db: Session = Depends(get_db)):
    pol = policy()
    return {
        "policy": {
            **pol,
            "note": "O scan mais recente de cada projeto nunca é apagado. 0 = nunca apagar. Configure por variável de ambiente.",
        },
        "stored": {
            "auditEntries": db.query(AuditLogModel).count(),
            "scans": db.query(ScanRun).count(),
            "findings": db.query(FindingModel).count(),
        },
    }


@router.post("/retention/run")
def retention_run(db: Session = Depends(get_db)):
    expired = expire_risk_acceptances(db)
    return {"expiredRiskAcceptances": expired, "removed": purge(db)}


@metrics_router.get("/metrics", response_class=PlainTextResponse)
def metrics_endpoint(request: Request, db: Session = Depends(get_db)):
    """Formato Prometheus. Autoriza com o token do coletor (SENTINELA_METRICS_TOKEN) ou com sessão de administrador."""
    token = os.environ.get("SENTINELA_METRICS_TOKEN", "")
    header = request.headers.get("authorization", "")
    if token and header.lower().startswith("bearer ") and hmac.compare_digest(header[7:].strip(), token):
        return metrics.render(db)
    if not auth_enabled():
        return metrics.render(db)
    user = user_from_request(request, db)
    if user and user.role == "admin":
        return metrics.render(db)
    raise HTTPException(401, "Informe o token do coletor (SENTINELA_METRICS_TOKEN) ou entre como administrador.")
