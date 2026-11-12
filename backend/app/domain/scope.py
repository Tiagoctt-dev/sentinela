# Escopo e cobertura de um scan: diz o que foi executado, o que NÃO foi e por quê.
# É o que impede que um scan externo (sem login) seja lido como equivalente a
# um scan autenticado — o score só vale para o escopo efetivamente verificado.

from typing import Any

from .models import STATE, Finding
from .policy_catalog import CHECKS

EXECUTED = (STATE.VULNERABLE, STATE.LIKELY, STATE.PASSED, STATE.INCONCLUSIVE)
# O que cada verificação exige do projeto. Só o que está listado aqui conta como "pré-requisito ausente".
LOGIN_CHECKS = {"D-JWT-01", "D-JWT-02", "D-JWT-03", "D-AUTH-01", "D-EXPOSE-01"}


def _requirements(target: dict) -> dict[str, tuple[bool, str]]:
    """check_id -> (satisfeito, motivo quando não)."""
    auth = target.get("auth") or {}
    creds = target.get("_credentials") or []
    has_login = bool(auth.get("login"))
    can_register = bool(auth.get("register")) and bool(target.get("allowMutations"))
    has_users = bool(creds) or can_register
    two_users = len(creds) >= 2 or can_register
    has_common = any(c.get("role") != "admin" for c in creds) or can_register
    mut = bool(target.get("allowMutations"))
    ep = target.get("endpoints") or {}

    def need(ok: bool, why: str) -> tuple[bool, str]:
        return ok, ("" if ok else why)

    req: dict[str, tuple[bool, str]] = {}
    for cid in LOGIN_CHECKS:
        req[cid] = need(has_login and has_users and bool(auth.get("protectedProbe") or cid in ("D-JWT-03",)),
                        "Requer rota de login, rota protegida e ao menos um usuário de teste.")
    req["D-BOLA-01"] = need(bool(target.get("bola")) and has_login and two_users and mut,
                            "Requer rota de BOLA, login, dois usuários de teste e autorização para testes que alteram dados.")
    req["D-BFLA-0N"] = need(bool(target.get("bfla")) and has_login and has_common,
                            "Requer rotas administrativas, login e um usuário de papel comum.")
    req["D-BOLA-A1"] = need(has_login and two_users and any(c.get("resourceId") for c in creds),
                            "Requer spec OpenAPI com rotas /recurso/{id}, login, dois usuários de teste e o ID do recurso do dono.")
    req["D-BFLA-A1"] = need(has_login and has_common, "Requer spec OpenAPI, login e um usuário de papel comum.")
    req["D-MASS-01"] = need(bool(target.get("massAssignment")) and can_register,
                            "Requer campo privilegiado, rota de cadastro e autorização para testes que alteram dados.")
    req["D-AUTHZ-0N"] = need(bool(ep.get("protectedGet")), "Requer a lista de rotas que exigem login.")
    req["D-INTEG-01"] = need(bool(ep.get("webhook")), "Requer a rota de webhook.")
    req["D-INTEG-02"] = need(bool(ep.get("cron")), "Requer a rota de cron.")
    req["D-FLOW-02"] = need(has_login, "Requer a rota de login.")
    req["D-OIDC-01"] = need(bool(ep.get("authProviders")), "Requer a rota de provedores de autenticação.")
    for cid in ("D-SPEC-01", "D-SPEC-02", "D-FLOW-01", "D-SSRF-01", "D-DISC-01"):
        req[cid] = (True, "")  # dependem da spec; se ela não existir, o próprio probe devolve "não executado"
    return req


def _family(cid: str) -> str:
    if cid.startswith("D-AUTHZ-"):
        return "D-AUTHZ-0N"
    if cid.startswith("D-BFLA-") and cid != "D-BFLA-A1":
        return "D-BFLA-0N"
    return cid


def build_scope(target: dict, findings: list[Finding]) -> dict[str, Any]:
    has_code = bool(target.get("projectPath"))
    creds = target.get("_credentials") or []
    req = _requirements(target)

    seen: dict[str, list[Finding]] = {}
    for f in findings:
        seen.setdefault(_family(f.id), []).append(f)

    executed, not_run, not_applicable = [], [], []
    for c in CHECKS:
        cid = c["id"]
        if c["kind"] == "static" and not has_code:
            not_applicable.append({"id": cid, "title": c["title"], "reason": "Análise de código não aplicável: o projeto não informa a pasta do código."})
            continue
        fs = seen.get(cid, [])
        ok, why = req.get(cid, (True, ""))
        outcome = [f.state for f in fs]
        if any(s in EXECUTED for s in outcome):
            executed.append({"id": cid, "title": c["title"]})
        elif any(s == STATE.NOT_APPLICABLE for s in outcome) and not any(s in (STATE.NOT_RUN, STATE.ERROR) for s in outcome):
            not_applicable.append({"id": cid, "title": c["title"], "reason": (fs[0].detail or "Sem superfície aplicável.")})
        else:
            reason = why if not ok else (fs[0].detail if fs else "A verificação não produziu resultado neste scan.")
            if any(s == STATE.ERROR for s in outcome):
                reason = "Falha de execução: " + (fs[0].detail or "")
            not_run.append({"id": cid, "title": c["title"], "reason": reason})

    total = len(executed) + len(not_run)
    roles = sorted({c.get("role", "user") for c in creds})
    authenticated = bool(creds) and any(f.state in EXECUTED for f in findings if f.id.startswith(("D-BOLA", "D-JWT", "D-BFLA-0", "D-EXPOSE", "D-AUTH-01")))
    spec_found = any(f.id == "D-DISC-01" and f.state != STATE.NOT_RUN and (f.data or {}).get("specPath") for f in findings)

    limitations = []
    if not authenticated:
        limitations.append("Scan externo: sem usuários de teste, não foram executados BOLA, BFLA, JWT, exposição autenticada nem as demais verificações que exigem login.")
    if not has_code:
        limitations.append("Sem análise de código: a pasta do projeto não foi informada.")
    if not spec_found:
        limitations.append("Spec OpenAPI não encontrada: a descoberta e o teste automático de rotas ficaram limitados.")
    if not target.get("allowMutations"):
        limitations.append("Testes que alteram dados não foram autorizados: BOLA com escrita, BFLA com métodos de escrita e mass assignment não rodam.")

    return {
        "mode": "authenticated" if authenticated else "external",
        "credentials": {"count": len(creds), "roles": roles},
        "specFound": spec_found, "codeAnalyzed": has_code, "mutationsAllowed": bool(target.get("allowMutations")),
        "checksPlanned": total, "checksExecuted": len(executed),
        "coveragePct": round(100 * len(executed) / total) if total else 0,
        "notRun": not_run, "notApplicable": not_applicable,
        "limitations": limitations,
    }
