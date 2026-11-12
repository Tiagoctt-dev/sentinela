"""Cada política contra um alvo real de laboratório: versão vulnerável, versão segura e falsos positivos conhecidos.

Nomes dos testes carregam o id da verificação (ex.: test_D_BOLA_01_...) — scripts/gen_policy_docs.py usa isso
para ligar cada política aos seus testes na documentação.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import by_id

from app.domain import canary
from app.domain.models import STATE
from app.domain.spec_checks import canary_reachable

ALL_VULN = dict(
    bola_vulnerable=True, bfla_vulnerable=True, accept_alg_none=True, weak_secret=True, leak_public=True,
    leak_env=True, spec_marks_secured_but_open=True, security_headers=False,
)


@pytest.fixture()
def canary_server(monkeypatch):
    """Faz o papel do endpoint /api/canary do Sentinela, para o teste de SSRF."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            canary.record(self.path.rsplit("/", 1)[-1])
            self.send_response(200)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setenv("PUBLIC_API_URL", f"http://127.0.0.1:{httpd.server_address[1]}")
    yield
    httpd.shutdown()
    httpd.server_close()


def scan(run_scan_sync, target_cfg, lab_server, creds, **extra):
    cfg = target_cfg(lab_server, **extra)
    cfg["_credentials"] = creds
    return run_scan_sync(cfg)


# =============================================================================== alvo VULNERÁVEL
def test_alvo_vulneravel_e_detectado_com_evidencia(lab, creds, target_cfg, run_scan_sync, canary_server):
    r = scan(run_scan_sync, target_cfg, lab(**ALL_VULN, ssrf_vulnerable=True), creds)

    for check in ("D-BOLA-01", "D-BFLA-01", "D-BFLA-A1", "D-JWT-01", "D-JWT-02", "D-SPEC-01", "D-SPEC-02", "D-EXPO-01", "D-SSRF-01", "D-HEAD-01"):
        f = by_id(r, check)
        assert f["state"] == STATE.VULNERABLE, f"{check}: {f['state']} — {f['detail']}"
        assert f["confidence"] == "confirmed"
        assert f["evidence"], f"{check} sem evidência"
        assert f["meta"]["references"], f"{check} sem referências"

    assert r["policy"]["passed"] is False
    assert "D-BOLA-01" in r["policy"]["violations"]


def test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(bola_vulnerable=True), creds), "D-BOLA-01")
    assert f["state"] == STATE.VULNERABLE
    assert "controle" in f["evidence"]
    assert f["asset"]["method"] == "PUT" and f["asset"]["path"].startswith("/users/")


def test_D_SPEC_02_mascara_valores_sensiveis_na_evidencia(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(leak_public=True), creds), "D-SPEC-02")
    assert f["state"] == STATE.VULNERABLE
    assert "abc12345" not in f["evidence"] and "123.456.789-00" not in f["evidence"]
    obs = f["data"]["observations"]
    assert any(o["outcome"] == "sensitive" and o["path"] == "/publico/clientes" and o["httpStatus"] == 200 for o in obs)


# =============================================================================== alvo SEGURO
def test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica(lab, creds, target_cfg, run_scan_sync):
    r = scan(run_scan_sync, target_cfg, lab(rate_limit=True), creds)
    graves = [(f["id"], f["detail"]) for f in r["findings"]
              if f["state"] == STATE.VULNERABLE and f["severity"] in ("CRITICAL", "HIGH")]
    assert graves == []
    assert r["policy"]["passed"] is True
    for check in ("D-BOLA-01", "D-BFLA-01", "D-JWT-01", "D-JWT-02", "D-AUTH-01", "D-SPEC-01", "D-EXPO-01"):
        assert by_id(r, check)["state"] == STATE.PASSED


# =============================================================================== FALSOS POSITIVOS conhecidos
def test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado(lab, creds, target_cfg, run_scan_sync):
    """Se a rota responde 200 sem credencial, o 200 do token forjado não significa nada."""
    f = by_id(scan(run_scan_sync, target_cfg, lab(protected_is_public=True), creds), "D-JWT-01")
    assert f["state"] == STATE.INCONCLUSIVE
    assert "sem credencial" in f["detail"]


def test_D_BOLA_01_api_que_ignora_o_id_e_apenas_indicio(lab, creds, target_cfg, run_scan_sync):
    """A API aceita qualquer id (até inexistente): o 2xx não prova acesso ao objeto alheio."""
    r = scan(run_scan_sync, target_cfg, lab(bola_ignores_id=True), creds)
    f = by_id(r, "D-BOLA-01")
    assert f["state"] == STATE.LIKELY and f["confidence"] == "indicative"
    assert r["policy"]["passed"] is True  # indício não reprova a política


def test_D_BOLA_01_e_D_BFLA_01_401_nao_e_aprovacao(lab, creds, target_cfg, run_scan_sync):
    """401 = o token nem foi aceito; não prova que o controle de dono/papel existe."""
    r = scan(run_scan_sync, target_cfg, lab(always_401_on_put=True), creds)
    assert by_id(r, "D-BOLA-01")["state"] == STATE.INCONCLUSIVE
    assert by_id(r, "D-BFLA-01")["state"] == STATE.INCONCLUSIVE


def test_D_BFLA_A1_401_em_todas_as_rotas_e_inconclusivo(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(bfla_returns_401=True), creds), "D-BFLA-A1")
    assert f["state"] == STATE.INCONCLUSIVE


def test_D_RATE_01_rota_que_sempre_nega_nao_mede_rate_limit(lab, creds, target_cfg, run_scan_sync):
    # a primeira rota protegida responde 401 em toda a rajada
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-RATE-01")
    assert f["state"] == STATE.INCONCLUSIVE


def test_D_RATE_01_sem_429_na_raiz_e_apenas_indicio_e_com_429_passa(lab, creds, target_cfg, run_scan_sync):
    cfg = dict(endpoints={})
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds, **cfg), "D-RATE-01")
    assert f["state"] == STATE.LIKELY and f["confidence"] == "indicative"
    g = by_id(scan(run_scan_sync, target_cfg, lab(rate_limit=True), creds, **cfg), "D-RATE-01")
    assert g["state"] == STATE.PASSED


def test_D_CORS_01_sem_cabecalho_cors_e_aprovado_nao_pulado(lab, creds, target_cfg, run_scan_sync):
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-CORS-01")["state"] == STATE.PASSED


# =============================================================================== SSRF: alcance do canário
def test_D_SSRF_01_detecta_quando_o_alvo_busca_a_url(lab, creds, target_cfg, run_scan_sync, canary_server):
    f = by_id(scan(run_scan_sync, target_cfg, lab(ssrf_vulnerable=True), creds), "D-SSRF-01")
    assert f["state"] == STATE.VULNERABLE
    assert any(o["outcome"] == "ssrf_confirmed" and o["param"] == "url" for o in f["data"]["observations"])


def test_D_SSRF_01_sem_alcance_do_canario_ausencia_nao_descarta(monkeypatch):
    monkeypatch.delenv("PUBLIC_API_URL", raising=False)
    assert canary_reachable("http://127.0.0.1:8080") is True        # mesma máquina
    assert canary_reachable("http://api.banco.interno") is False     # não dá para afirmar alcance
    monkeypatch.setenv("PUBLIC_API_URL", "http://10.0.0.9:8000")
    assert canary_reachable("http://api.banco.interno") is True      # alcance declarado pelo operador


# =============================================================================== SEGURANÇA DO PRÓPRIO SCANNER
def test_sem_autorizacao_de_escrita_nenhum_metodo_que_altera_dados_e_enviado(lab, creds, target_cfg, run_scan_sync):
    server = lab(bola_vulnerable=True, bfla_vulnerable=True)
    r = scan(run_scan_sync, target_cfg, server, creds, allowMutations=False)
    assert by_id(r, "D-BOLA-01")["state"] == STATE.NOT_RUN
    assert by_id(r, "D-BFLA-01")["state"] == STATE.NOT_RUN
    mutating = [c for c in server.behavior.calls if c[0] in ("PUT", "DELETE", "PATCH")]
    assert mutating == [], f"métodos de escrita enviados sem autorização: {mutating}"


def test_regressao_scanner_nunca_chama_rota_com_nome_de_acao(lab, creds, target_cfg, run_scan_sync):
    """Incidente real: GET /createdb do VAmPI apagava o banco do alvo."""
    server = lab()
    scan(run_scan_sync, target_cfg, server, creds)
    assert server.behavior.hits == 0
    assert ("GET", "/createdb") not in server.behavior.calls


def test_D_BOLA_01_com_escrita_autorizada_executa(lab, creds, target_cfg, run_scan_sync):
    server = lab(bola_vulnerable=True)
    scan(run_scan_sync, target_cfg, server, creds)
    assert any(c[0] == "PUT" for c in server.behavior.calls)


# =============================================================================== FALHAS DE REDE
def test_alvo_indisponivel_gera_erro_de_execucao_nao_aprovacao(run_scan_sync):
    r = run_scan_sync({"name": "fora do ar", "baseUrl": "http://127.0.0.1:9"})
    f = by_id(r, "D-ENV-00")
    assert f["state"] == STATE.ERROR
    assert not [x for x in r["findings"] if x["state"] == STATE.PASSED]
    assert r["scope"]["checksExecuted"] == 0


def test_login_de_teste_invalido_gera_erro_e_nao_aprova_verificacoes_autenticadas(lab, target_cfg, run_scan_sync):
    cfg = target_cfg(lab())
    cfg["_credentials"] = [{"label": "x", "role": "user", "username": "ana", "password": "errada", "resourceId": None}]
    r = run_scan_sync(cfg)
    assert by_id(r, "D-AUTH-00")["state"] == STATE.ERROR
    assert all(f["id"] not in ("D-JWT-01", "D-BOLA-01") for f in r["findings"])
