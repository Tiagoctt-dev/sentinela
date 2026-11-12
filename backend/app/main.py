import asyncio
import logging
import os
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# Carregador mínimo de .env (evita depender de python-dotenv em runtime local).
def _load_dotenv():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


_load_dotenv()

from . import metrics  # noqa: E402
from .api.routes_admin import metrics_router, router as admin_router  # noqa: E402
from .api.routes_ai import router as ai_router  # noqa: E402
from .api.routes_auth import audit_router, router as auth_router, users_router  # noqa: E402
from .api.routes_schedules import router as schedules_router  # noqa: E402
from .auth import admin_only, guard, user_from_request  # noqa: E402
from .db.models import AuditLogModel  # noqa: E402
from .scheduler import scheduler_loop  # noqa: E402
from .api.routes_canary import router as canary_router  # noqa: E402
from .api.routes_credentials import router as credentials_router  # noqa: E402
from .api.routes_dashboard import router as dashboard_router  # noqa: E402
from .api.routes_findings import router as findings_router  # noqa: E402
from .api.routes_integrations import router as integrations_router  # noqa: E402
from .api.routes_policies import router as policies_router  # noqa: E402
from .api.routes_scans import router as scans_router  # noqa: E402
from .api.routes_stats import router as stats_router  # noqa: E402
from .api.routes_targets import router as targets_router, seed_file_targets  # noqa: E402
from .db.models import Base  # noqa: E402
from .db.session import SessionLocal, engine  # noqa: E402
from sqlalchemy import text  # noqa: E402

app = FastAPI(title="Sentinela", description="Scanner de segurança de APIs — backend")

logging.basicConfig(level=os.environ.get("SENTINELA_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Total-Count", "X-Request-ID"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    # create_all não altera tabelas existentes — colunas novas entram aqui.
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS origin VARCHAR"))
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS scope JSON"))
            for col, typ in (("state", "VARCHAR"), ("confidence", "VARCHAR"), ("asset", "JSON"), ("meta", "JSON"),
                             ("resolution_expires_at", "TIMESTAMPTZ"), ("resolution_by", "VARCHAR")):
                conn.execute(text(f"ALTER TABLE findings ADD COLUMN IF NOT EXISTS {col} {typ}"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0"))
            # índices (create_all só os cria junto com a tabela; nomes iguais aos do SQLAlchemy para não duplicar)
            for name, table, col in (
                ("ix_findings_run_id", "findings", "run_id"), ("ix_findings_finding_id", "findings", "finding_id"),
                ("ix_scan_runs_target_id", "scan_runs", "target_id"), ("ix_scan_runs_created_at", "scan_runs", "created_at"),
            ):
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({col})"))
    encrypt_legacy_secrets()
    backfill_states()
    seed_file_targets()


def backfill_states() -> None:
    """Scans anteriores ao modelo estado/confiança ganham os campos novos, derivados das mesmas regras."""
    from .db.models import FindingModel
    from .domain.classify import apply
    from .domain.models import Finding

    db = SessionLocal()
    try:
        rows = db.query(FindingModel).filter(FindingModel.state.is_(None)).all()
        for r in rows:
            f = Finding(id=r.finding_id, category=r.category, title=r.title, status=r.status, severity=r.severity,
                        detail=r.detail or "", recommendation=r.recommendation or "", evidence=r.evidence or "",
                        source=r.source, owasp=r.owasp or "", data=r.data)
            apply(f)
            r.state, r.confidence, r.asset, r.meta, r.status = f.state, f.confidence, f.asset, f.meta, f.status
        db.commit()
    finally:
        db.close()


def encrypt_legacy_secrets() -> None:
    """Segredos de integrações gravados em texto puro por versões anteriores passam a ser criptografados."""
    from .db.models import GithubIntegrationModel, SlackIntegrationModel
    from .security import encrypt, is_encrypted

    db = SessionLocal()
    try:
        for g in db.query(GithubIntegrationModel).all():
            if not is_encrypted(g.token):
                g.token = encrypt(g.token)
        for s in db.query(SlackIntegrationModel).all():
            if not is_encrypted(s.webhook_url):
                s.webhook_url = encrypt(s.webhook_url)
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
async def start_scheduler():
    if os.environ.get("SENTINELA_SCHEDULER", "on").lower() not in ("off", "false", "0"):
        app.state.scheduler_task = asyncio.create_task(scheduler_loop())


_AUDITED = ("POST", "PUT", "PATCH", "DELETE")


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    if request.url.path.startswith("/api/"):
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        metrics.record_request(request.method, response.status_code)
    path = request.url.path
    if request.method in _AUDITED and path.startswith("/api/") and not path.startswith("/api/canary"):
        db = SessionLocal()
        try:
            email = getattr(request.state, "user_email", None)
            if not email and path == "/api/auth/login":
                email = "(tentativa de login)"
            if not email:
                u = user_from_request(request, db)
                email = u.email if u else None
            db.add(AuditLogModel(user_email=email, method=request.method, path=path, status_code=response.status_code,
                                 ip=request.client.host if request.client else None))
            db.commit()
        except Exception:  # noqa: BLE001 — auditoria nunca derruba a requisição
            logging.getLogger(__name__).exception("Falha ao gravar auditoria")
        finally:
            db.close()
    return response


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Rotas abertas: login/primeiro acesso e o canário do teste de SSRF.
app.include_router(auth_router)
app.include_router(canary_router)
app.include_router(metrics_router)  # autoriza por token do coletor ou sessão de admin
# Leitura para qualquer usuário logado; escrita exige analista ou administrador.
for _r in (targets_router, scans_router, findings_router, stats_router, policies_router, ai_router, schedules_router, dashboard_router):
    app.include_router(_r, dependencies=[Depends(guard)])
# Áreas sensíveis: só administradores.
for _r in (credentials_router, integrations_router):
    app.include_router(_r, dependencies=[Depends(admin_only)])
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(admin_router)
