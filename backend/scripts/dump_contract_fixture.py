"""Gera fixtures REAIS de contrato (scan, rotas e dashboard) a partir do próprio backend contra o alvo de
laboratório. O front-end as usa nos testes para provar que a interface exibe exatamente o que a API devolve.

Uso (na pasta backend):  .venv/Scripts/python scripts/dump_contract_fixture.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

tmp = Path(tempfile.mkdtemp(prefix="sentinela-fixture-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(tmp / 'f.db').as_posix()}"
os.environ["SENTINELA_SECRET_KEY"] = "kT3N0eLZq9v8QfJmWcR2yH5uX7bA1dEgP4sVnC6zIoM="
os.environ["SENTINELA_SCHEDULER"] = "off"
os.environ["SENTINELA_AUTH"] = "off"

from fastapi.testclient import TestClient  # noqa: E402

import app.main as m  # noqa: E402
from lab_server import Behavior, LabServer  # noqa: E402

OUT = ROOT.parent / "frontend" / "src" / "test" / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)

with TestClient(m.app) as c, LabServer(Behavior(bola_vulnerable=True, accept_alg_none=True, leak_public=True, bola_ignores_id=False)) as lab:
    tid = c.post("/api/targets", json={
        "name": "Laboratório", "baseUrl": lab.url, "allowMutations": True,
        "auth": {"login": "/login", "tokenField": "token", "scheme": "Bearer ", "protectedProbe": "/me"},
        "endpoints": {"protectedGet": ["/api/contas"]},
        "bola": {"method": "PUT", "path": "/users/{victim}/email", "body": {"email": "x@y.z"}},
        "bfla": [{"method": "DELETE", "path": "/users/bruno"}],
    }).json()["id"]
    for label, role, user in (("Ana", "user", "ana"), ("Bruno", "user", "bruno"), ("Root", "admin", "root")):
        c.post(f"/api/targets/{tid}/credentials", json={"label": label, "role": role, "username": user, "password": "Senha#123"})
    external_tid = c.post("/api/targets", json={"name": "Somente URL", "baseUrl": lab.url}).json()["id"]

    first = c.post("/api/scans", json={"targetId": tid, "ai": False, "static": False}, timeout=180).json()
    lab.behavior.bola_vulnerable = False
    scan = c.post("/api/scans", json={"targetId": tid, "ai": False, "static": False}, timeout=180).json()
    external = c.post("/api/scans", json={"targetId": external_tid, "ai": False, "static": False}, timeout=180).json()

    payloads = {
        "scan.json": scan,
        "scan-external.json": external,
        "routes.json": c.get(f"/api/scans/{scan['id']}/routes").json(),
        "dashboard.json": c.get(f"/api/dashboard?targetId={tid}").json(),
        "findings.json": c.get("/api/findings").json(),
        "compare.json": c.get(f"/api/scans/{scan['id']}/compare").json(),
    }
    for name, data in payloads.items():
        (OUT / name).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print("fixtures gravadas em", OUT, "|", {k: (len(v) if isinstance(v, list) else "obj") for k, v in payloads.items()})
    assert first["id"] != scan["id"]
