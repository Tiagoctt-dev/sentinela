"""Endpoints do Sentinela: autenticação/papéis, persistência, isolamento entre execuções,
segredos, limites de execução e a diferença REAL entre scan externo e autenticado."""

import pytest
from conftest import by_id
from fastapi.testclient import TestClient

from app.domain.models import STATE

PASSWORD = "SenhaForte#2026"


@pytest.fixture(scope="module")
def client():
    import app.main as m

    with TestClient(m.app) as c:
        yield c


@pytest.fixture(scope="module")
def tokens(client):
    r = client.post("/api/auth/bootstrap", json={"name": "Admin", "email": "admin@t.io", "password": PASSWORD})
    assert r.status_code == 201
    admin = {"Authorization": "Bearer " + r.json()["token"]}
    out = {"admin": admin}
    for role in ("analyst", "viewer"):
        assert client.post("/api/users", headers=admin, json={"name": role, "email": f"{role}@t.io", "password": PASSWORD, "role": role}).status_code == 201
        tok = client.post("/api/auth/login", json={"email": f"{role}@t.io", "password": PASSWORD}).json()["token"]
        out[role] = {"Authorization": "Bearer " + tok}
    return out


def create_target(client, headers, server, *, creds=True, **extra):
    body = {
        "name": "Lab", "baseUrl": server.url, "allowMutations": True,
        "auth": {"login": "/login", "tokenField": "token", "scheme": "Bearer ", "protectedProbe": "/me"},
        "endpoints": {"protectedGet": ["/api/contas"]},
        "bola": {"method": "PUT", "path": "/users/{victim}/email", "body": {"email": "x@y.z"}},
        "bfla": [{"method": "DELETE", "path": "/users/bruno"}],
    }
    body.update(extra)
    r = client.post("/api/targets", headers=headers, json=body)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    if creds:
        for label, role, user in (("Ana", "user", "ana"), ("Bruno", "user", "bruno"), ("Root", "admin", "root")):
            rc = client.post(f"/api/targets/{tid}/credentials", headers=headers, json={"label": label, "role": role, "username": user, "password": "Senha#123"})
            assert rc.status_code == 201
    return tid


def run(client, headers, tid, **kw):
    r = client.post("/api/scans", headers=headers, json={"targetId": tid, "ai": False, "static": False, **kw})
    assert r.status_code == 200, r.text
    return r.json()


# =============================================================================== autenticação e papéis
def test_rotas_exigem_login_e_papeis_sao_respeitados(client, tokens, lab):
    assert client.get("/api/targets").status_code == 401
    assert client.get("/api/targets", headers={"Authorization": "Bearer forjado.x.y"}).status_code == 401
    server = lab()
    assert client.post("/api/targets", headers=tokens["viewer"], json={"name": "x", "baseUrl": server.url}).status_code == 403
    assert client.get("/api/targets", headers=tokens["viewer"]).status_code == 200
    tid = create_target(client, tokens["admin"], server)
    assert client.post("/api/scans", headers=tokens["viewer"], json={"targetId": tid}).status_code == 403
    assert client.get(f"/api/targets/{tid}/credentials", headers=tokens["analyst"]).status_code == 403
    assert client.get("/api/integrations/github", headers=tokens["analyst"]).status_code == 403
    assert client.get("/api/audit", headers=tokens["analyst"]).status_code == 403


def test_credenciais_nunca_voltam_pela_api_e_ficam_criptografadas(client, tokens, lab):
    tid = create_target(client, tokens["admin"], lab())
    listed = client.get(f"/api/targets/{tid}/credentials", headers=tokens["admin"]).json()
    assert listed and all("password" not in c and c["passwordSet"] for c in listed)
    from app.db.models import CredentialModel
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        raw = db.query(CredentialModel).filter_by(target_id=tid).all()
        assert raw and all("Senha#123" not in r.password_enc and r.password_enc.startswith("gAAAA") for r in raw)
    finally:
        db.close()


# =============================================================================== persistência e rastreabilidade
def test_o_que_a_api_devolve_e_o_que_o_banco_guarda(client, tokens, lab):
    tid = create_target(client, tokens["analyst"] if False else tokens["admin"], lab(bola_vulnerable=True, leak_public=True))
    scan = run(client, tokens["analyst"], tid)
    stored = client.get(f"/api/scans/{scan['id']}", headers=tokens["analyst"]).json()

    assert stored["scope"] == scan["scope"] and stored["createdBy"] == "analyst@t.io"
    assert [f["id"] for f in stored["findings"]] == [f["id"] for f in scan["findings"]]
    for a, b in zip(scan["findings"], stored["findings"]):
        for campo in ("state", "confidence", "status", "severity", "asset", "meta", "evidence"):
            assert a[campo] == b[campo], f"{a['id']}.{campo} mudou ao persistir"

    # a lista global de achados mostra exatamente os estados do banco
    glob = {f["id"]: f for f in client.get("/api/findings?onlyActionable=false", headers=tokens["analyst"]).json() if f["scanId"] == scan["id"]}
    assert glob["D-BOLA-01"]["state"] == STATE.VULNERABLE
    assert set(glob) == {f["id"] for f in stored["findings"]}

    # os totais por estado batem com a lista
    from collections import Counter
    contados = {k: v for k, v in Counter(f["state"] for f in stored["findings"]).items()}
    persistidos = {k: v for k, v in stored["totals"]["states"].items() if v}
    assert contados == persistidos, "totais por estado divergem da lista de achados"
    legado = Counter(f["status"] for f in stored["findings"])
    assert {k: v for k, v in stored["totals"].items() if k in ("PASS", "FAIL", "WARN", "SKIP") and v} == dict(legado)


def test_filtros_de_achados_por_estado_e_confianca(client, tokens, lab):
    tid = create_target(client, tokens["admin"], lab(bola_ignores_id=True))
    scan = run(client, tokens["admin"], tid)
    likely = client.get("/api/findings?state=likely", headers=tokens["admin"]).json()
    assert any(f["scanId"] == scan["id"] and f["id"] == "D-BOLA-01" and f["confidence"] == "indicative" for f in likely)
    confirmed = client.get("/api/findings?confidence=confirmed", headers=tokens["admin"]).json()
    assert all(f["confidence"] == "confirmed" for f in confirmed)


def test_execucoes_nao_sobrescrevem_umas_as_outras(client, tokens, lab):
    a = create_target(client, tokens["admin"], lab(bola_vulnerable=True))
    b = create_target(client, tokens["admin"], lab())
    s1 = run(client, tokens["admin"], a)
    s2 = run(client, tokens["admin"], b)
    s3 = run(client, tokens["admin"], a)
    assert len({s1["id"], s2["id"], s3["id"]}) == 3
    antes = client.get(f"/api/scans/{s1['id']}", headers=tokens["admin"]).json()
    assert antes["findings"] == s1["findings"]  # reexecutar o mesmo alvo não altera o scan anterior
    assert {f["id"] for f in s1["findings"] if f["state"] == STATE.VULNERABLE} == {f["id"] for f in s3["findings"] if f["state"] == STATE.VULNERABLE}
    assert by_id(s2, "D-BOLA-01")["state"] == STATE.PASSED  # o outro alvo não herdou o resultado


# =============================================================================== a diferença REAL entre os modos
def test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes(client, tokens, lab):
    server = lab(bola_vulnerable=True, accept_alg_none=True, bfla_vulnerable=True)
    ext_t = create_target(client, tokens["admin"], server, creds=False)
    aut_t = create_target(client, tokens["admin"], server, creds=True)
    ext, aut = run(client, tokens["admin"], ext_t), run(client, tokens["admin"], aut_t)

    # 1) o scan externo NÃO executa as verificações que exigem login — e diz isso
    assert ext["scope"]["mode"] == "external" and aut["scope"]["mode"] == "authenticated"
    ext_not_run = {x["id"] for x in ext["scope"]["notRun"]}
    for check in ("D-BOLA-01", "D-JWT-01", "D-JWT-02", "D-AUTH-01", "D-EXPOSE-01", "D-BFLA-0N"):
        assert check in ext_not_run, f"{check} deveria constar como não executado no modo externo"
        assert check not in {x["id"] for x in aut["scope"]["notRun"]}
    assert any("sem usuários de teste" in x for x in ext["scope"]["limitations"])

    # 2) a cobertura declarada reflete a diferença
    assert aut["scope"]["checksExecuted"] > ext["scope"]["checksExecuted"]
    assert aut["scope"]["coveragePct"] > ext["scope"]["coveragePct"]

    # 3) os achados autenticados realmente existem só no modo autenticado
    ids_ext = {f["id"] for f in ext["findings"]}
    ids_aut = {f["id"] for f in aut["findings"]}
    assert {"D-BOLA-01", "D-JWT-01"} <= ids_aut and not ({"D-BOLA-01", "D-JWT-01"} & ids_ext)
    assert by_id(aut, "D-BOLA-01")["state"] == STATE.VULNERABLE
    assert by_id(aut, "D-JWT-01")["state"] == STATE.VULNERABLE

    # 4) as verificações em comum produzem o MESMO resultado (nada é inventado a mais no modo autenticado)
    # (verificações que dependem de login aparecem como "não executadas" no modo externo — isso é esperado e declarado)
    executadas_nos_dois = {cid for cid in ids_ext & ids_aut if by_id(ext, cid)["state"] != STATE.NOT_RUN}
    assert len(executadas_nos_dois) >= 8
    for cid in executadas_nos_dois:
        assert by_id(ext, cid)["state"] == by_id(aut, cid)["state"], f"{cid} difere entre os modos sem motivo"


def test_o_score_nao_e_igual_por_coincidencia_de_teto(client, tokens, lab):
    """Com o teto só para falha CONFIRMADA, um scan externo sem prova não herda o mesmo 50 do autenticado."""
    server = lab(bola_vulnerable=True, accept_alg_none=True)
    ext = run(client, tokens["admin"], create_target(client, tokens["admin"], server, creds=False))
    aut = run(client, tokens["admin"], create_target(client, tokens["admin"], server, creds=True))
    assert aut["overall"] <= 50
    assert ext["overall"] > aut["overall"]


def test_scan_por_url_avulsa_e_externo_e_declara_limites(client, tokens, lab):
    server = lab()
    r = client.post("/api/scans", headers=tokens["admin"], json={"url": server.url, "ai": False, "static": False})
    assert r.status_code == 200
    scope = r.json()["scope"]
    assert scope["mode"] == "external" and scope["limitations"]
    assert scope["checksPlanned"] == scope["checksExecuted"] + len(scope["notRun"])


# =============================================================================== comparação entre execuções
def test_comparacao_nao_trata_nao_executado_como_corrigido(client, tokens, lab):
    server = lab(bola_vulnerable=True)
    tid = create_target(client, tokens["admin"], server)
    first = run(client, tokens["admin"], tid)
    assert by_id(first, "D-BOLA-01")["state"] == STATE.VULNERABLE

    server.behavior.bola_vulnerable = False  # correção aplicada
    second = run(client, tokens["admin"], tid)
    cmp1 = client.get(f"/api/scans/{second['id']}/compare", headers=tokens["admin"]).json()
    assert "D-BOLA-01" in {f["id"] for f in cmp1["fixed"]}

    # remover as credenciais: BOLA deixa de rodar -> NÃO pode contar como corrigido
    server.behavior.bola_vulnerable = True
    run(client, tokens["admin"], tid)
    for c in client.get(f"/api/targets/{tid}/credentials", headers=tokens["admin"]).json():
        client.delete(f"/api/targets/{tid}/credentials/{c['id']}", headers=tokens["admin"])
    fourth = run(client, tokens["admin"], tid)
    cmp2 = client.get(f"/api/scans/{fourth['id']}/compare", headers=tokens["admin"]).json()
    assert "D-BOLA-01" not in {f["id"] for f in cmp2["fixed"]}
    assert "D-BOLA-01" in {f["id"] for f in cmp2["notComparable"]}


# =============================================================================== segredos e destinos
def test_token_do_github_e_url_do_slack_ficam_criptografados(client, tokens):
    gh = client.post("/api/integrations/github", headers=tokens["admin"], json={"repo": "org/repo", "token": "ghp_SEGREDO_MUITO_LONGO_1234567890"}).json()
    sl = client.post("/api/integrations/slack", headers=tokens["admin"], json={"name": "c", "webhookUrl": "https://hooks.slack.com/services/T000/B000/SUPERSECRETO"}).json()
    assert "SEGREDO" not in str(gh) and "SUPERSECRETO" not in str(sl)
    assert gh["tokenMasked"].endswith("7890")

    from app.db.models import GithubIntegrationModel, SlackIntegrationModel
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        g = db.query(GithubIntegrationModel).filter_by(id=gh["id"]).one()
        s = db.query(SlackIntegrationModel).filter_by(id=sl["id"]).one()
        assert g.token.startswith("gAAAA") and "SEGREDO" not in g.token
        assert s.webhook_url.startswith("gAAAA") and "SUPERSECRETO" not in s.webhook_url
    finally:
        db.close()


def test_migracao_criptografa_segredos_antigos_em_texto_puro(client):
    from app.db.models import GithubIntegrationModel
    from app.db.session import SessionLocal
    from app.main import encrypt_legacy_secrets

    db = SessionLocal()
    try:
        row = GithubIntegrationModel(repo="a/b", token="ghp_texto_puro_antigo", enabled=True)
        db.add(row)
        db.commit()
        rid = row.id
    finally:
        db.close()
    encrypt_legacy_secrets()
    db = SessionLocal()
    try:
        assert db.query(GithubIntegrationModel).filter_by(id=rid).one().token.startswith("gAAAA")
    finally:
        db.close()


def test_destinos_perigosos_sao_recusados_em_projetos_e_integracoes(client, tokens):
    h = tokens["admin"]
    assert client.post("/api/targets", headers=h, json={"name": "x", "baseUrl": "http://169.254.169.254/latest"}).status_code == 400
    assert client.post("/api/scans", headers=h, json={"url": "http://169.254.169.254/", "ai": False}).status_code == 400
    assert client.post("/api/integrations/webhooks", headers=h, json={"name": "x", "url": "http://169.254.169.254/x"}).status_code == 400
    assert client.post("/api/integrations/webhooks", headers=h, json={"name": "x", "url": "texto solto http://x"}).status_code == 400


# =============================================================================== limites de execução
def test_scan_que_excede_o_tempo_e_interrompido_e_nao_persiste_resultado_parcial(client, tokens, lab, monkeypatch):
    import app.api.routes_scans as rs

    tid = create_target(client, tokens["admin"], lab())
    before = len(client.get(f"/api/scans?targetId={tid}", headers=tokens["admin"]).json())
    async def lento(*a, **k):
        import asyncio
        await asyncio.sleep(5)

    monkeypatch.setattr(rs, "run_scan", lento)
    monkeypatch.setattr(rs, "SCAN_TIMEOUT_S", 0.2)
    r = client.post("/api/scans", headers=tokens["admin"], json={"targetId": tid, "ai": False, "static": False})
    assert r.status_code == 504 and "limite" in r.json()["detail"]
    assert len(client.get(f"/api/scans?targetId={tid}", headers=tokens["admin"]).json()) == before


def test_login_bloqueia_apos_tentativas_repetidas(client, tokens):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"email": "viewer@t.io", "password": "errada"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "viewer@t.io", "password": PASSWORD}).status_code == 429


# =============================================================================== políticas
def test_catalogo_de_politicas_lista_todas_as_verificacoes_executadas(client, tokens, lab):
    tid = create_target(client, tokens["admin"], lab(bola_vulnerable=True))
    scan = run(client, tokens["admin"], tid)
    cat = client.get("/api/policies/owasp", headers=tokens["viewer"]).json()
    catalog_ids = {c["id"] for item in cat["items"] for c in item["checks"]}
    for f in scan["findings"]:
        base = "D-AUTHZ-0N" if f["id"].startswith("D-AUTHZ-") else "D-BFLA-0N" if f["id"].startswith("D-BFLA-0") else f["id"]
        if f["id"] in ("D-ENV-00", "D-AUTH-00"):
            continue
        assert base in catalog_ids, f"{f['id']} executado mas ausente do catálogo de políticas"
