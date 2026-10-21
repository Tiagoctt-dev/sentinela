import asyncio
import logging
import os
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

from .api.routes_ai import router as ai_router  # noqa: E402
from .api.routes_auth import audit_router, router as auth_router, users_router  # noqa: E402
from .api.routes_schedules import router as schedules_router  # noqa: E402
from .auth import admin_only, guard, user_from_request  # noqa: E402
from .db.models import AuditLogModel  # noqa: E402
from .scheduler import scheduler_loop  # noqa: E402
from .api.routes_canary import router as canary_router  # noqa: E402
from .api.routes_credentials import router as credentials_router  # noqa: E402
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    # create_all não altera tabelas existentes — colunas novas entram aqui.
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS origin VARCHAR"))
    seed_file_targets()


@app.on_event("startup")
async def start_scheduler():
    if os.environ.get("SENTINELA_SCHEDULER", "on").lower() not in ("off", "false", "0"):
        app.state.scheduler_task = asyncio.create_task(scheduler_loop())


_AUDITED = ("POST", "PUT", "PATCH", "DELETE")


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    response = await call_next(request)
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
# Leitura para qualquer usuário logado; escrita exige analista ou administrador.
for _r in (targets_router, scans_router, findings_router, stats_router, policies_router, ai_router, schedules_router):
    app.include_router(_r, dependencies=[Depends(guard)])
# Áreas sensíveis: só administradores.
for _r in (credentials_router, integrations_router):
    app.include_router(_r, dependencies=[Depends(admin_only)])
app.include_router(users_router)
app.include_router(audit_router)
