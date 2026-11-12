"""Rotas/verificações e dashboard: derivados só de dados persistidos e com totais consistentes com as listas."""

import pytest
from fastapi.testclient import TestClient

from test_api_modes_and_persistence import PASSWORD, create_target, run  # noqa: F401  (reuso dos helpers)


@pytest.fixture(scope="module")
def client():
    import app.main as m

    with TestClient(m.app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/auth/bootstrap", json={"name": "Admin", "email": "a@t.io", "password": PASSWORD})
    if r.status_code == 201:
        return {"Authorization": "Bearer " + r.json()["token"]}
    return {"Authorization": "Bearer " + client.post("/api/auth/login", json={"email": "a@t.io", "password": PASSWORD}).json()["token"]}


def test_dashboard_vazio_explica_o_que_falta(client, admin):
    d = client.get("/api/dashboard", headers=admin).json()
    assert d["projects"] == 0 and d["coverage"]["avgPct"] is None and d["routes"] is None
    assert d["missing"] and "Nenhum scan" in d["missing"][0]
    assert d["trend"] == [] and d["trendNote"]


def test_rotas_e_verificacoes_separam_estados_e_os_totais_batem(client, admin, lab):
    tid = create_target(client, admin, lab(bola_vulnerable=True, leak_public=True))
    scan = run(client, admin, tid)
    v = client.get(f"/api/scans/{scan['id']}/routes", headers=admin).json()
    rotas = {(r["method"], r["path"]): r for r in v["routes"]}

    # rota exposta: vulnerável, com o código HTTP e a verificação que provou
    pub = rotas[("GET", "/publico/clientes")]
    assert pub["state"] == "vulnerable"
    assert any(c["checkId"] == "D-SPEC-02" and c["httpStatus"] == 200 and c["state"] == "vulnerable" for c in pub["checks"])

    # a rota com nome de ação foi DESCOBERTA mas nunca chamada: pendente, não "aprovada"
    created = rotas[("GET", "/createdb")]
    assert created["known"] and not created["tested"] and created["state"] == "not_tested"

    # o estado da ROTA é o pior das verificações; o de cada verificação aparece separado.
    # /api/contas: acesso anônimo negado (aprovado) + rate limit que só recebeu 401 (inconclusivo) => rota inconclusiva, não "segura"
    contas = rotas[("GET", "/api/contas")]
    por_check = {c["checkId"]: c["state"] for c in contas["checks"]}
    assert por_check["D-AUTHZ-01"] == "passed" and por_check["D-RATE-01"] == "inconclusive"
    assert contas["state"] == "inconclusive"

    # contadores consistentes com a lista
    c = v["counts"]
    assert c["routes"] == len(v["routes"])
    assert sum(c["byState"].values()) == c["routes"]
    known = [r for r in v["routes"] if r["known"]]
    assert c["known"] == len(known)
    assert c["tested"] + c["pending"] == c["known"], "testadas + pendentes devem somar as rotas conhecidas"
    assert c["tested"] == sum(1 for r in known if r["tested"]) and c["pending"] >= 1
    # caminhos sondados que não existem (ex.: /.env => 404) não são rotas
    assert ("GET", "/.env") not in rotas and not any(r["path"].startswith("/actuator") for r in v["routes"])
    assert sum(c["checks"].values()) == sum(len(r["checks"]) for r in v["routes"])


def test_rotas_scan_externo_lista_verificacoes_pendentes_com_motivo(client, admin, lab):
    tid = create_target(client, admin, lab(), creds=False)
    v = client.get(f"/api/scans/{run(client, admin, tid)['id']}/routes", headers=admin).json()
    pend = {x["id"]: x for x in v["pendingChecks"]}
    assert "D-BOLA-01" in pend and pend["D-BOLA-01"]["reason"]


def test_dashboard_numeros_batem_com_o_ultimo_scan_de_cada_projeto(client, admin, lab):
    server = lab(bola_vulnerable=True, accept_alg_none=True)
    tid = create_target(client, admin, server)
    run(client, admin, tid)
    scan = run(client, admin, tid)
    d = client.get(f"/api/dashboard?targetId={tid}", headers=admin).json()

    vuln = [f for f in scan["findings"] if f["state"] in ("vulnerable", "likely")]
    assert sum(d["findings"]["bySeverity"].values()) == len(vuln)
    assert d["findings"]["byState"]["vulnerable"] == sum(1 for f in scan["findings"] if f["state"] == "vulnerable")
    assert sum(d["findings"]["byState"].values()) == len(scan["findings"])
    assert sum(c["vulnerable"] + c["likely"] for c in d["findings"]["byCategory"]) == len(vuln)
    assert d["coverage"]["avgPct"] == scan["scope"]["coveragePct"]

    # evolução: só aparece com 2+ execuções comparáveis e usa os valores persistidos
    assert len(d["trend"]) >= 2
    assert d["trend"][-1]["scanId"] == scan["id"] and d["trend"][-1]["score"] == scan["overall"]


def test_dashboard_geral_pede_um_projeto_para_mostrar_evolucao(client, admin):
    d = client.get("/api/dashboard", headers=admin).json()
    assert d["trend"] == [] and "Selecione um projeto" in d["trendNote"]
