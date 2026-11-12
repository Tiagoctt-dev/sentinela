"""Regras puras: classificação de estado, score, política, proteção de rede e base editorial."""

import pytest

from app.domain.classify import apply
from app.domain.knowledge import KNOWLEDGE, knowledge_for
from app.domain.models import STATE, STATUS, finding
from app.domain.policy import evaluate_policy
from app.domain.policy_catalog import CHECKS
from app.domain.scoring import score
from app.netguard import TargetNotAllowed, validate_url


def mk(id="D-HEAD-01", status=STATUS.FAIL, severity="MEDIUM", category="HEADERS", detail="", **kw):
    return finding(id=id, category=category, title="t", status=status, severity=severity, detail=detail, **kw)


# ----------------------------------------------------------------------------- estado
@pytest.mark.parametrize("status,detail,expected", [
    (STATUS.SKIP, "Falha ao requisitar (ConnectError).", STATE.ERROR),
    (STATUS.SKIP, "Não consegui alcançar http://x (ConnectError).", STATE.ERROR),
    (STATUS.SKIP, "Cadastre um usuário de papel comum.", STATE.NOT_RUN),
    (STATUS.SKIP, "Algoritmo RS256 não é HMAC — não se aplica.", STATE.NOT_APPLICABLE),
    (STATUS.SKIP, "Só 3/20 requisições completaram.", STATE.INCONCLUSIVE),
])
def test_skip_nunca_vira_aprovado_e_distingue_o_motivo(status, detail, expected):
    f = apply(mk(status=status, detail=detail))
    assert f.state == expected
    assert f.status == STATUS.SKIP


def test_pass_e_aprovado_somente_no_escopo_verificado():
    f = apply(mk(status=STATUS.PASS))
    assert f.state == STATE.PASSED
    assert "escopo" in f.meta["scopeNote"]


def test_falha_com_prova_direta_e_vulneravel_confirmada():
    f = apply(mk(id="D-JWT-01", status=STATUS.FAIL, severity="CRITICAL", category="TOKEN_SESSION"))
    assert (f.state, f.confidence) == (STATE.VULNERABLE, "confirmed")


def test_falha_de_verificacao_indicativa_vira_provavel_e_nao_confirmada():
    f = apply(mk(id="D-RATE-01", status=STATUS.WARN, category="TRANSPORT"))
    assert (f.state, f.confidence) == (STATE.LIKELY, "indicative")
    assert f.status == STATUS.WARN


def test_falha_indicativa_com_status_fail_e_rebaixada_para_provavel():
    f = apply(mk(id="S-AUTHZ-02", status=STATUS.FAIL, severity="CRITICAL", category="AUTHORIZATION"))
    assert f.state == STATE.LIKELY
    assert f.status == STATUS.WARN


def test_http_404_em_alerta_e_inconclusivo_nao_vulnerabilidade():
    f = apply(mk(id="D-AUTHZ-01", status=STATUS.WARN, severity="CRITICAL", category="AUTHORIZATION",
                 detail="Retornou 404 — rota não encontrada no app que está rodando."))
    assert f.state == STATE.INCONCLUSIVE


def test_estado_explicito_do_probe_e_respeitado():
    f = apply(mk(id="D-BOLA-01", status=STATUS.SKIP, state=STATE.INCONCLUSIVE, detail="401"))
    assert f.state == STATE.INCONCLUSIVE


def test_ativo_e_http_sao_extraidos_da_evidencia():
    f = apply(mk(evidence="GET http://h.local/api/x?url=a\n→ HTTP 200"))
    assert f.asset["method"] == "GET" and f.asset["path"] == "/api/x" and f.asset["httpStatus"] == 200
    assert f.asset["param"] == "url"


# ----------------------------------------------------------------------------- score
def test_so_falha_confirmada_aplica_o_teto_de_score():
    confirmed = [apply(mk(id="D-JWT-01", status=STATUS.FAIL, severity="CRITICAL", category="TOKEN_SESSION"))]
    likely = [apply(mk(id="S-AUTHZ-02", status=STATUS.FAIL, severity="CRITICAL", category="AUTHORIZATION"))]
    assert score(confirmed)["overall"] <= 50
    assert score(likely)["overall"] > 50  # indício crítico pesa metade e não derruba o teto


def test_indicio_pesa_menos_que_prova():
    base = dict(severity="HIGH")
    prova = score([apply(mk(id="D-CORS-01", status=STATUS.FAIL, category="HEADERS", **base))])
    indicio = score([apply(mk(id="D-FLOW-01", status=STATUS.WARN, category="AUTHORIZATION", **base))])
    assert prova["overall"] < indicio["overall"]


def test_nao_executado_nao_altera_score_nem_conta_como_avaliado():
    r = score([apply(mk(status=STATUS.SKIP, detail="Cadastre credenciais", category="AUTHORIZATION"))])
    assert r["overall"] == 0  # sem nada avaliado não há score
    cat = next(c for c in r["categories"] if c["key"] == "AUTHORIZATION")
    assert cat["score"] is None and cat["evaluated"] == 0
    assert r["states"][STATE.NOT_RUN] == 1


def test_totais_por_estado_batem_com_a_lista():
    fs = [apply(mk(status=s, detail=d)) for s, d in [(STATUS.PASS, ""), (STATUS.FAIL, ""), (STATUS.SKIP, "Cadastre x")]]
    r = score(fs)
    assert sum(r["states"].values()) == len(fs)
    assert sum(r["totals"].values()) == len(fs)


# ----------------------------------------------------------------------------- política
def test_politica_reprova_so_com_critico_confirmado():
    confirmed = apply(mk(id="D-JWT-01", status=STATUS.FAIL, severity="CRITICAL", category="TOKEN_SESSION"))
    likely = apply(mk(id="S-AUTHZ-02", status=STATUS.FAIL, severity="CRITICAL", category="AUTHORIZATION"))
    assert evaluate_policy([confirmed])["passed"] is False
    res = evaluate_policy([likely])
    assert res["passed"] is True and res["pending"] == ["S-AUTHZ-02"]


# ----------------------------------------------------------------------------- base editorial
def test_toda_verificacao_do_catalogo_tem_texto_editorial_completo():
    campos = ("summary", "technical", "impact", "exploitation", "prerequisites", "passWhen", "failWhen", "limitations", "severityReason", "proof")
    for c in CHECKS:
        k = knowledge_for(c["id"])
        assert k, f"sem base editorial: {c['id']}"
        for campo in campos:
            assert k[campo] not in (None, ""), f"{c['id']} sem {campo}"
        assert k["proof"] in ("confirmed", "indicative")


def test_referencias_incluem_owasp_e_cwe():
    f = apply(finding(id="D-SSRF-01", category="INPUT_VALIDATION", title="t", status=STATUS.FAIL, severity="CRITICAL", owasp="API7:2023"))
    labels = [r["label"] for r in f.meta["references"]]
    assert any("API7:2023" in x for x in labels) and "CWE-918" in labels


def test_chaves_do_conhecimento_existem_no_catalogo():
    ids = {c["id"] for c in CHECKS}
    assert set(KNOWLEDGE) - ids == set(), "conhecimento para verificação inexistente no catálogo"


# ----------------------------------------------------------------------------- netguard
def test_metadata_de_nuvem_e_sempre_bloqueado():
    for url in ("http://169.254.169.254/latest/meta-data", "http://metadata.google.internal/", "http://[fd00:ec2::254]/"):
        with pytest.raises(TargetNotAllowed):
            validate_url(url)


def test_esquema_e_formato_invalidos():
    for url in ("file:///etc/passwd", "ftp://x.com", "https://", "http://a b.com", ""):
        with pytest.raises(TargetNotAllowed):
            validate_url(url)


def test_loopback_permitido_por_padrao_e_bloqueavel(monkeypatch):
    assert validate_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    monkeypatch.setenv("SENTINELA_BLOCK_PRIVATE_TARGETS", "on")
    for url in ("http://127.0.0.1", "http://10.0.0.5", "http://192.168.1.10"):
        with pytest.raises(TargetNotAllowed):
            validate_url(url)


def test_allowlist_restringe_destinos(monkeypatch):
    monkeypatch.setenv("SENTINELA_TARGET_ALLOWLIST", "127.0.0.1")
    assert validate_url("http://127.0.0.1:9")
    with pytest.raises(TargetNotAllowed):
        validate_url("http://localhost:9")


def test_localhost_e_loopback_ipv6_sao_permitidos_por_padrao():
    """Regressão: 'localhost' resolve para ::1, que o Python classifica como 'reservado' — não pode ser bloqueado."""
    assert validate_url("http://localhost:5002") == "http://localhost:5002"
    assert validate_url("http://[::1]:8000/") == "http://[::1]:8000"
    with pytest.raises(TargetNotAllowed):
        validate_url("http://[::ffff:169.254.169.254]/")  # IPv4 de metadados embutido em IPv6
    with pytest.raises(TargetNotAllowed):
        validate_url("http://0.0.0.0:80")
