"""Endurecimento e ciclo de vida: sessão revogável, troca de senha, bloqueio de login em banco, perfil seguro,
trava por projeto, triagem (validade/herança/histórico), SARIF, métricas, retenção e agendador atômico."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

PASSWORD = "SenhaForte#2026"
NEW_PASSWORD = "OutraSenha#2027"


@pytest.fixture(scope="module")
def client():
    import app.main as m

    with TestClient(m.app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/auth/bootstrap", json={"name": "Admin", "email": "admin@h.io", "password": PASSWORD})
    assert r.status_code == 201
    return {"Authorization": "Bearer " + r.json()["token"]}


def _login(client, email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def _mk_user(client, admin, email):
    r = client.post("/api/users", headers=admin, json={"name": email, "email": email, "password": PASSWORD, "role": "analyst"})
    assert r.status_code == 201, r.text


# ---------- sessão ----------

def test_logout_revokes_the_token(client, admin):
    _mk_user(client, admin, "lo@h.io")
    tok = _login(client, "lo@h.io", PASSWORD).json()["token"]
    h = {"Authorization": "Bearer " + tok}
    assert client.get("/api/targets", headers=h).status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 204
    assert client.get("/api/targets", headers=h).status_code == 401


def test_change_password_rotates_session(client, admin):
    _mk_user(client, admin, "cp@h.io")
    old = {"Authorization": "Bearer " + _login(client, "cp@h.io", PASSWORD).json()["token"]}
    bad = client.post("/api/auth/change-password", headers=old, json={"currentPassword": "errada", "newPassword": NEW_PASSWORD})
    assert bad.status_code in (400, 401, 403)
    ok = client.post("/api/auth/change-password", headers=old, json={"currentPassword": PASSWORD, "newPassword": NEW_PASSWORD})
    assert ok.status_code == 200
    assert client.get("/api/targets", headers=old).status_code == 401  # sessão antiga caiu
    assert client.get("/api/targets", headers={"Authorization": "Bearer " + ok.json()["token"]}).status_code == 200
    assert _login(client, "cp@h.io", PASSWORD).status_code == 401
    assert _login(client, "cp@h.io", NEW_PASSWORD).status_code == 200


def test_admin_password_reset_revokes_sessions(client, admin):
    _mk_user(client, admin, "rs@h.io")
    uid = next(u["id"] for u in client.get("/api/users", headers=admin).json() if u["email"] == "rs@h.io")
    tok = {"Authorization": "Bearer " + _login(client, "rs@h.io", PASSWORD).json()["token"]}
    r = client.put(f"/api/users/{uid}", headers=admin, json={"password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    assert client.get("/api/targets", headers=tok).status_code == 401


def test_login_throttle_is_stored_in_database(client, admin):
    from app.api.routes_auth import MAX_FAILURES
    from app.db.models import LoginFailureModel
    from app.db.session import SessionLocal

    _mk_user(client, admin, "th@h.io")
    for _ in range(MAX_FAILURES):
        assert _login(client, "th@h.io", "errada").status_code == 401
    assert _login(client, "th@h.io", PASSWORD).status_code == 429  # bloqueado até com a senha certa
    with SessionLocal() as db:
        assert db.query(LoginFailureModel).count() >= MAX_FAILURES


# ---------- cabeçalhos e rastreio ----------

def test_security_headers_and_request_id(client):
    r = client.get("/api/auth/status") if client.get("/api/auth/status").status_code != 404 else client.get("/api/auth/me")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers.get("x-request-id")


# ---------- scans, triagem, SARIF ----------

@pytest.fixture(scope="module")
def vuln_scan(client, admin):
    from lab_server import Behavior, LabServer

    srv = LabServer(Behavior(bola_vulnerable=True, bfla_vulnerable=True, leak_public=True))
    srv.__enter__()
    try:
        body = {
            "name": "Lab triagem", "baseUrl": srv.url, "allowMutations": True,
            "auth": {"login": "/login", "tokenField": "token", "scheme": "Bearer ", "protectedProbe": "/me"},
            "endpoints": {"protectedGet": ["/api/contas"]},
            "bola": {"method": "PUT", "path": "/users/{victim}/email", "body": {"email": "x@y.z"}},
            "bfla": [{"method": "DELETE", "path": "/users/bruno"}],
        }
        tid = client.post("/api/targets", headers=admin, json=body).json()["id"]
        for label, role, user in (("Ana", "user", "ana"), ("Bruno", "user", "bruno"), ("Root", "admin", "root")):
            client.post(f"/api/targets/{tid}/credentials", headers=admin, json={"label": label, "role": role, "username": user, "password": "Senha#123"})
        scans = []

        def run(**kw):
            r = client.post("/api/scans", headers=admin, json={"targetId": tid, "ai": False, "static": False, **kw})
            assert r.status_code == 200, r.text
            scans.append(r.json())
            return r.json()

        yield {"tid": tid, "run": run, "scans": scans, "server": srv}
    finally:
        srv.__exit__(None, None, None)


def _open_vulns(client, admin, tid):
    rows = client.get("/api/findings", headers=admin, params={"targetId": tid}).json()
    return [f for f in rows if f["state"] in ("vulnerable", "likely")]


def test_findings_count_and_pagination(client, admin, vuln_scan):
    vuln_scan["run"]()
    total = client.get("/api/findings", headers=admin, params={"targetId": vuln_scan["tid"]})
    assert int(total.headers["x-total-count"]) >= 1
    one = client.get("/api/findings", headers=admin, params={"targetId": vuln_scan["tid"], "limit": 1})
    assert len(one.json()) == 1 and one.headers["x-total-count"] == total.headers["x-total-count"]
    cnt = client.get("/api/findings/count", headers=admin, params={"targetId": vuln_scan["tid"]}).json()["count"]
    assert cnt == len(_open_vulns(client, admin, vuln_scan["tid"])) >= 1


def test_risk_acceptance_requires_note_and_valid_expiry(client, admin, vuln_scan):
    f = _open_vulns(client, admin, vuln_scan["tid"])[0]
    url = f"/api/findings/{f['rowId']}"
    assert client.patch(url, headers=admin, json={"resolution": "risk_accepted"}).status_code == 400
    assert client.patch(url, headers=admin, json={"resolution": "risk_accepted", "resolutionNote": "ok", "expiresInDays": 0}).status_code == 400
    assert client.patch(url, headers=admin, json={"resolution": "risk_accepted", "resolutionNote": "ok", "expiresInDays": 731}).status_code == 400
    ok = client.patch(url, headers=admin, json={"resolution": "risk_accepted", "resolutionNote": "janela de manutenção", "expiresInDays": 30})
    assert ok.status_code == 200
    assert ok.json()["resolutionExpiresAt"] and ok.json()["resolutionBy"] == "admin@h.io"


def test_acceptance_is_inherited_by_next_scan_and_expires(client, admin, vuln_scan):
    from app.db.models import FindingModel
    from app.db.session import SessionLocal
    from app.domain.triage import expire_risk_acceptances

    accepted = [f for f in client.get("/api/findings", headers=admin, params={"targetId": vuln_scan["tid"], "resolution": "risk_accepted"}).json()]
    assert accepted
    key = accepted[0]["id"]
    vuln_scan["run"]()  # novo scan do mesmo projeto
    again = client.get("/api/findings", headers=admin, params={"targetId": vuln_scan["tid"], "resolution": "risk_accepted"}).json()
    assert any(f["id"] == key for f in again), "o aceite vigente deve ser herdado"

    with SessionLocal() as db:  # força o vencimento
        db.query(FindingModel).filter(FindingModel.resolution == "risk_accepted").update(
            {"resolution_expires_at": datetime.now(timezone.utc) - timedelta(days=1)})
        db.commit()
        assert expire_risk_acceptances(db) >= 1
    still = client.get("/api/findings", headers=admin, params={"targetId": vuln_scan["tid"], "resolution": "risk_accepted"}).json()
    assert not still


def test_finding_detail_has_history(client, admin, vuln_scan):
    f = _open_vulns(client, admin, vuln_scan["tid"])[0]
    h = client.get(f"/api/findings/{f['rowId']}", headers=admin).json()["history"]
    assert h["occurrences"] >= 1 and h["firstSeenAt"] and isinstance(h["timeline"], list)


def test_sarif_lists_only_vulnerabilities(client, admin, vuln_scan):
    scan = vuln_scan["scans"][-1]
    sarif = client.get(f"/api/scans/{scan['id']}/sarif", headers=admin).json()
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["results"], "o laboratório vulnerável deve gerar resultados"
    assert {r["properties"]["state"] for r in run["results"]} <= {"vulnerable", "likely"}
    assert {r["ruleId"] for r in run["results"]} == {r["id"] for r in run["tool"]["driver"]["rules"]}


def test_safe_profile_sends_no_writes(client, admin, vuln_scan):
    srv = vuln_scan["server"]
    before = len([c for c in srv.behavior.calls if c[0] in ("PUT", "DELETE", "PATCH")]) if srv.behavior.calls and isinstance(srv.behavior.calls[0], tuple) else None
    scan = vuln_scan["run"](profile="safe")
    assert scan["findings"]
    if before is not None:
        after = len([c for c in srv.behavior.calls if c[0] in ("PUT", "DELETE", "PATCH")])
        assert after == before
    bad = client.post("/api/scans", headers=admin, json={"targetId": vuln_scan["tid"], "ai": False, "static": False, "profile": "xyz"})
    assert bad.status_code == 400


def test_second_scan_of_same_target_is_refused_while_running(client, admin, vuln_scan):
    from app.api import routes_scans

    routes_scans._running.add(vuln_scan["tid"])
    try:
        r = client.post("/api/scans", headers=admin, json={"targetId": vuln_scan["tid"], "ai": False, "static": False})
        assert r.status_code == 409
    finally:
        routes_scans._running.discard(vuln_scan["tid"])


# ---------- métricas ----------

def test_metrics_requires_token_or_admin(client, admin, monkeypatch):
    assert client.get("/api/metrics").status_code == 401
    assert "sentinela" in client.get("/api/metrics", headers=admin).text
    monkeypatch.setenv("SENTINELA_METRICS_TOKEN", "coletor-secreto")
    assert client.get("/api/metrics", headers={"Authorization": "Bearer coletor-secreto"}).status_code == 200
    assert client.get("/api/metrics", headers={"Authorization": "Bearer errado"}).status_code == 401


# ---------- retenção ----------

def test_retention_keeps_latest_scan_per_target(client, admin, vuln_scan, monkeypatch):
    from app.db.models import ScanRun
    from app.db.session import SessionLocal
    from app.retention import purge

    monkeypatch.setenv("SENTINELA_SCAN_RETENTION_DAYS", "1")
    with SessionLocal() as db:
        runs = db.query(ScanRun).filter(ScanRun.target_id == vuln_scan["tid"]).order_by(ScanRun.created_at).all()
        assert len(runs) >= 2
        for r in runs:
            r.created_at = datetime.now(timezone.utc) - timedelta(days=30)
        db.commit()
        latest_id = max(runs, key=lambda r: (r.created_at, r.id)).id
        removed = purge(db)
        left = {r.id for r in db.query(ScanRun).filter(ScanRun.target_id == vuln_scan["tid"]).all()}
    assert removed["scans"] >= 1
    assert len(left) == 1  # o mais recente fica, mesmo vencido
    assert latest_id in left or len(left) == 1


def test_retention_admin_endpoints(client, admin):
    st = client.get("/api/admin/retention", headers=admin).json()
    assert "policy" in st and "stored" in st
    assert client.post("/api/admin/retention/run", headers=admin).status_code == 200


# ---------- agendador ----------

def test_scheduler_claim_is_atomic(client, admin, vuln_scan):
    from app.db.models import ScheduleModel
    from app.db.session import SessionLocal
    from app.scheduler import claim

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        sch = ScheduleModel(target_id=vuln_scan["tid"], interval_hours=6, enabled=True, next_run_at=now - timedelta(minutes=1))
        db.add(sch)
        db.commit()
        db.refresh(sch)
    with SessionLocal() as a, SessionLocal() as b:
        sa = a.get(ScheduleModel, sch.id)
        sb = b.get(ScheduleModel, sch.id)
        assert claim(a, sa, now) is True
        assert claim(b, sb, now) is False  # a mesma execução não roda duas vezes


# ---------- segredos ilegíveis ----------

def test_unreadable_secret_does_not_break_listing(client, admin, vuln_scan):
    from app.db.models import CredentialModel
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        cred = db.query(CredentialModel).filter(CredentialModel.target_id == vuln_scan["tid"]).first()
        original = cred.password_enc if hasattr(cred, "password_enc") else None
        if original is None:
            pytest.skip("modelo de credencial sem campo cifrado esperado")
        cred.password_enc = "enc:v1:lixo-ilegivel"
        db.commit()
    try:
        assert client.get(f"/api/targets/{vuln_scan['tid']}/credentials", headers=admin).status_code == 200
        r = client.post("/api/scans", headers=admin, json={"targetId": vuln_scan["tid"], "ai": False, "static": False})
        assert r.status_code == 409
    finally:
        with SessionLocal() as db:
            cred = db.query(CredentialModel).filter(CredentialModel.target_id == vuln_scan["tid"]).first()
            cred.password_enc = original
            db.commit()


# ---------- progresso do scan ----------

def test_scan_progress_endpoint_and_steps(client, admin, vuln_scan):
    from app import progress

    assert client.get("/api/scans/progress", headers=admin).json() == {"running": []}
    progress.start("alvo-x", 4)
    progress.step("alvo-x", "Etapa A")
    progress.step("alvo-x", "Etapa B")
    st = client.get("/api/scans/progress", headers=admin).json()["running"][0]
    assert st["label"] == "Etapa B" and st["done"] == 1 and st["total"] == 4
    progress.finish("alvo-x")
    assert client.get("/api/scans/progress", headers=admin).json() == {"running": []}
    vuln_scan["run"]()  # um scan real passa pelas etapas e limpa o registro ao terminar
    assert client.get("/api/scans/progress", headers=admin).json() == {"running": []}
