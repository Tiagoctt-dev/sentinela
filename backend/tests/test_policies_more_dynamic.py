"""Políticas dinâmicas restantes contra o alvo de laboratório (complementa test_policies_vs_lab.py)."""

import pytest
from conftest import by_id

from app.domain.models import STATE

pytestmark = pytest.mark.filterwarnings("ignore")


def scan(run_scan_sync, target_cfg, server, creds, mutate=None, **extra):
    cfg = target_cfg(server, **extra)
    cfg["_credentials"] = creds
    if mutate:
        mutate(cfg)
    return run_scan_sync(cfg)


# ------------------------------------------------------------------------------------------- tokens e exposição
def test_D_JWT_03_token_sem_exp_e_vulneravel_de_severidade_media(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(jwt_no_exp=True), creds), "D-JWT-03")
    assert f["state"] == STATE.VULNERABLE and f["severity"] == "MEDIUM"
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-JWT-03")["state"] == STATE.PASSED


def test_D_JWT_02_segredo_fraco_e_detectado_e_segredo_forte_passa(lab, creds, target_cfg, run_scan_sync):
    assert by_id(scan(run_scan_sync, target_cfg, lab(weak_secret=True), creds), "D-JWT-02")["state"] == STATE.VULNERABLE
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-JWT-02")["state"] == STATE.PASSED


def test_D_EXPOSE_01_campo_sensivel_na_resposta_autenticada(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(leak_me=True), creds), "D-EXPOSE-01")
    assert f["state"] == STATE.VULNERABLE and "password_hash" in f["evidence"]
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-EXPOSE-01")["state"] == STATE.PASSED


def test_D_AUTH_01_rota_protegida_aberta_reprova(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(protected_is_public=True), creds), "D-AUTH-01")
    assert f["state"] == STATE.VULNERABLE


def test_D_AUTHZ_0N_rota_declarada_protegida_que_responde_sem_sessao(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(spec_marks_secured_but_open=True), creds), "D-AUTHZ-01")
    assert f["state"] == STATE.VULNERABLE and f["asset"]["path"] == "/api/contas"
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-AUTHZ-01")["state"] == STATE.PASSED


def test_D_AUTHZ_0N_rota_inexistente_e_inconclusiva_nao_vulneravel(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds, endpoints={"protectedGet": ["/rota-que-nao-existe"]}), "D-AUTHZ-01")
    assert f["state"] == STATE.INCONCLUSIVE


# ------------------------------------------------------------------------------------------- mass assignment
def _mass(cfg):
    cfg["auth"]["register"] = "/register"
    cfg["massAssignment"] = {"field": "admin", "verifyMePath": "data.admin"}


def test_D_MASS_01_campo_privilegiado_aceito_no_cadastro(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(mass_assign_vulnerable=True), creds, mutate=_mass), "D-MASS-01")
    assert f["state"] == STATE.VULNERABLE and f["severity"] == "HIGH"
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds, mutate=_mass), "D-MASS-01")["state"] == STATE.PASSED


def test_D_MASS_01_sem_autorizacao_de_escrita_nao_cria_conta_no_alvo(lab, creds, target_cfg, run_scan_sync):
    server = lab(mass_assign_vulnerable=True)
    f = by_id(scan(run_scan_sync, target_cfg, server, creds, mutate=_mass, allowMutations=False), "D-MASS-01")
    assert f["state"] == STATE.NOT_RUN
    assert ("POST", "/register") not in server.behavior.calls


# ------------------------------------------------------------------------------------------- configuração e cabeçalhos
def test_D_INFO_01_divulgacao_de_tecnologia_e_versao(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(leak_server_header=True), creds), "D-INFO-01")
    assert f["state"] == STATE.VULNERABLE and f["severity"] == "LOW" and "Werkzeug" in f["evidence"]
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-INFO-01")["state"] == STATE.PASSED


def test_D_HEAD_01_cabecalhos_ausentes_e_presentes(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(security_headers=False), creds), "D-HEAD-01")
    assert f["state"] == STATE.VULNERABLE and "ausentes" in f["evidence"]
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-HEAD-01")["state"] == STATE.PASSED


def test_D_TLS_01_alvo_em_http_e_apontado_com_severidade_baixa(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-TLS-01")
    assert f["state"] == STATE.VULNERABLE and f["severity"] == "LOW"


def test_D_CORS_01_origem_arbitraria_com_credenciais(lab, creds, target_cfg, run_scan_sync):
    # o laboratório não reflete origens; o teste garante o caminho "aprovado" já coberto e a evidência da requisição
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-CORS-01")
    assert f["state"] == STATE.PASSED and "Origin: https://attacker-controlled.test" in f["evidence"]


# ------------------------------------------------------------------------------------------- integridade
def test_D_INTEG_01_webhook_sem_assinatura(lab, creds, target_cfg, run_scan_sync):
    ep = {"protectedGet": ["/api/contas"], "webhook": "/webhook"}
    assert by_id(scan(run_scan_sync, target_cfg, lab(webhook_unsigned=True), creds, endpoints=ep), "D-INTEG-01")["state"] == STATE.VULNERABLE
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds, endpoints=ep), "D-INTEG-01")["state"] == STATE.PASSED
    ausente = {"protectedGet": ["/api/contas"], "webhook": "/webhook-inexistente"}
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds, endpoints=ausente), "D-INTEG-01")["state"] == STATE.INCONCLUSIVE


def test_D_INTEG_02_cron_sem_segredo(lab, creds, target_cfg, run_scan_sync):
    ep = {"protectedGet": ["/api/contas"], "cron": "/cron"}
    f = by_id(scan(run_scan_sync, target_cfg, lab(cron_open=True), creds, endpoints=ep), "D-INTEG-02")
    assert f["state"] == STATE.LIKELY and f["confidence"] == "indicative"  # 200 pode ser benigno: é indício
    assert by_id(scan(run_scan_sync, target_cfg, lab(), creds, endpoints=ep), "D-INTEG-02")["state"] == STATE.PASSED


def test_D_OIDC_01_endpoint_de_provedores(lab, creds, target_cfg, run_scan_sync):
    ep = {"protectedGet": ["/api/contas"], "authProviders": "/auth/providers"}
    assert by_id(scan(run_scan_sync, target_cfg, lab(has_providers=True), creds, endpoints=ep), "D-OIDC-01")["state"] == STATE.PASSED
    assert by_id(scan(run_scan_sync, target_cfg, lab(has_providers=False), creds, endpoints=ep), "D-OIDC-01")["state"] == STATE.INCONCLUSIVE


def test_D_FLOW_02_login_com_e_sem_limite_de_tentativas(lab, creds, target_cfg, run_scan_sync):
    sem = by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-FLOW-02")
    assert sem["state"] == STATE.LIKELY and sem["confidence"] == "indicative"
    com = by_id(scan(run_scan_sync, target_cfg, lab(login_rate_limit=True), creds), "D-FLOW-02")
    assert com["state"] == STATE.PASSED


def test_D_FLOW_01_fluxos_sensiveis_sem_429_documentado_sao_indicio(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-FLOW-01")
    assert f["state"] == STATE.LIKELY
    assert f["data"]["documentationOnly"] is True  # avalia a documentação, não o comportamento


# ------------------------------------------------------------------------------------------- descoberta e SOAP
def test_D_DISC_01_endpoints_da_spec_fora_do_inventario(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(), creds), "D-DISC-01")
    assert f["state"] == STATE.LIKELY
    assert any(e["path"] == "/publico/clientes" for e in f["data"]["endpoints"])


def test_D_DISC_01_spec_ausente_e_nao_executado_nao_aprovado(lab, creds, target_cfg, run_scan_sync):
    r = scan(run_scan_sync, target_cfg, lab(), creds, openapiUrl="/nao-existe.json")
    assert by_id(r, "D-SPEC-01")["state"] == STATE.NOT_RUN


def test_D_SOAP_01_e_D_SOAP_02_wsdl_exposto_e_politica_ws_security(lab, creds, target_cfg, run_scan_sync):
    r = scan(run_scan_sync, target_cfg, lab(wsdl="plain"), creds)
    assert by_id(r, "D-SOAP-01")["state"] == STATE.VULNERABLE
    assert by_id(r, "D-SOAP-02")["state"] == STATE.LIKELY  # sem política declarada: indício (TLS pode proteger)
    r2 = scan(run_scan_sync, target_cfg, lab(wsdl="secured"), creds)
    assert by_id(r2, "D-SOAP-02")["state"] == STATE.PASSED
    r3 = scan(run_scan_sync, target_cfg, lab(), creds)
    assert not [f for f in r3["findings"] if f["id"].startswith("D-SOAP")]  # sem serviço SOAP, nenhum ruído


def test_D_BFLA_0N_e_D_BFLA_A1_usuario_admin_nao_e_o_alvo_do_teste(lab, creds, target_cfg, run_scan_sync):
    r = scan(run_scan_sync, target_cfg, lab(bfla_vulnerable=True), creds)
    assert by_id(r, "D-BFLA-01")["state"] == STATE.VULNERABLE
    assert by_id(r, "D-BFLA-A1")["state"] == STATE.VULNERABLE


def test_D_JWT_01_evidencia_mostra_requisicao_e_controle(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(accept_alg_none=True), creds), "D-JWT-01")
    assert f["state"] == STATE.VULNERABLE
    assert "GET " in f["evidence"] and "alg=none" in f["evidence"] and "controle (sem credencial)" in f["evidence"]


def test_D_JWT_02_nunca_registra_o_segredo_quebrado(lab, creds, target_cfg, run_scan_sync):
    r = scan(run_scan_sync, target_cfg, lab(weak_secret=True), creds)
    f = by_id(r, "D-JWT-02")
    assert f["state"] == STATE.VULNERABLE
    blob = " ".join([f["detail"], f["evidence"], str(f["meta"])])
    assert '"secret"' not in blob and "Segredo \"secret\"" not in blob
    assert "valor omitido" in f["evidence"] or "não é registrado" in f["detail"]


def _with_resource_ids(creds):
    ids = {"ana": "c-ana", "bruno": "c-bruno"}
    return [{**c, "resourceId": ids.get(c["username"])} for c in creds]


def test_D_BOLA_A1_rota_com_id_vulneravel_e_confirmada(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(bola_path="vulnerable"), _with_resource_ids(creds)), "D-BOLA-A1")
    assert f["state"] == STATE.VULNERABLE and f["confidence"] == "confirmed"
    assert "/api/contas/" in f["evidence"] and "controle" in f["evidence"]


def test_D_BOLA_A1_rota_segura_passa(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(bola_path="secure"), _with_resource_ids(creds)), "D-BOLA-A1")
    assert f["state"] == STATE.PASSED


def test_D_BOLA_A1_sem_id_do_recurso_nao_executa(lab, creds, target_cfg, run_scan_sync):
    f = by_id(scan(run_scan_sync, target_cfg, lab(bola_path="vulnerable"), creds), "D-BOLA-A1")
    assert f["state"] == STATE.NOT_RUN


def test_D_BOLA_A1_nao_aparece_sem_rota_com_id_na_spec(lab, creds, target_cfg, run_scan_sync):
    r = scan(run_scan_sync, target_cfg, lab(), _with_resource_ids(creds))
    assert not [f for f in r["findings"] if f["id"] == "D-BOLA-A1"]
