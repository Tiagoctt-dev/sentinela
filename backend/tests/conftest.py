import os
import sys
import tempfile
from pathlib import Path

# Banco isolado em arquivo temporário, login desligado por padrão (testes de auth o ligam) e sem agendador.
_tmp = Path(tempfile.mkdtemp(prefix="sentinela-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["SENTINELA_SECRET_KEY"] = "kT3N0eLZq9v8QfJmWcR2yH5uX7bA1dEgP4sVnC6zIoM="
os.environ["SENTINELA_SCHEDULER"] = "off"
os.environ["SENTINELA_AUTH"] = "on"
for k in ("GEMINI_API_KEY", "GROQ_API_KEY", "SENTINELA_BLOCK_PRIVATE_TARGETS", "SENTINELA_TARGET_ALLOWLIST", "PUBLIC_API_URL"):
    os.environ.pop(k, None)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

from lab_server import Behavior, LabServer, PASSWORD  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def clean_db():
    """Cada módulo de teste começa com banco vazio e sem contadores de login acumulados."""
    from app.db.models import Base
    from app.db.session import engine

    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
    yield


@pytest.fixture()
def lab():
    """Fábrica de alvos de laboratório: lab(bola_vulnerable=True) -> servidor em execução."""
    servers = []

    def make(**flags) -> LabServer:
        s = LabServer(Behavior(**flags))
        s.__enter__()
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.__exit__(None, None, None)


@pytest.fixture()
def creds():
    return [
        {"label": "Ana", "role": "user", "username": "ana", "password": PASSWORD, "resourceId": None},
        {"label": "Bruno", "role": "user", "username": "bruno", "password": PASSWORD, "resourceId": None},
        {"label": "Root", "role": "admin", "username": "root", "password": PASSWORD, "resourceId": None},
    ]


@pytest.fixture()
def target_cfg():
    """Configuração de projeto completa (login, BOLA, BFLA) para um servidor de laboratório."""
    def make(server: LabServer, **extra) -> dict:
        cfg = {
            "name": "Laboratório", "baseUrl": server.url, "allowMutations": True,
            "auth": {"login": "/login", "tokenField": "token", "scheme": "Bearer ", "protectedProbe": "/me"},
            "endpoints": {"protectedGet": ["/api/contas"]},
            "bola": {"method": "PUT", "path": "/users/{victim}/email", "body": {"email": "x@y.z"}},
            "bfla": [{"method": "DELETE", "path": "/users/bruno"}],
        }
        cfg.update(extra)
        return cfg

    return make


@pytest.fixture()
def run_scan_sync():
    import asyncio

    from app.domain.pipeline import run_scan

    def run(cfg: dict, **kw):
        return asyncio.run(run_scan(cfg, ai=False, static=False, **kw))

    return run


def by_id(result: dict, check_id: str) -> dict:
    matches = [f for f in result["findings"] if f["id"] == check_id]
    assert matches, f"{check_id} ausente; achados: {[f['id'] for f in result['findings']]}"
    return matches[0]
