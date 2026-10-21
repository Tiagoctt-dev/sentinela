# Probes ATIVOS: exercitam a API como um atacante faria — registram usuários,
# autenticam e tentam abusos reais (BOLA entre dois usuários, aceitação de
# token inválido, mass assignment). Rodam apenas quando o alvo declara `auth`.
# Porte de lib/active-probes.mjs.

import random
import string
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .jwt_utils import decode_jwt, find_weak_hmac_secret, forge_alg_none
from .models import STATUS, Finding, finding

TIMEOUT_S = 8.0

SENSITIVE_KEYS = {"password", "password_hash", "senha", "ssn", "cpf", "credit_card", "cartao", "secret", "api_key", "apikey", "private_key"}


def _find_sensitive_keys(obj, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{path}.{k}" if path else k
            if k.lower() in SENSITIVE_KEYS and v not in (None, "", False):
                hits.append(full)
            hits.extend(_find_sensitive_keys(v, full))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):  # não desce em listas gigantes
            hits.extend(_find_sensitive_keys(v, f"{path}[{i}]"))
    return hits


@dataclass
class ReqResult:
    ok: bool
    status: Optional[int] = None
    body: Any = None
    error: Optional[str] = None


async def _req(client: httpx.AsyncClient, url: str, method: str = "GET", headers: dict | None = None, json: Any = None) -> ReqResult:
    try:
        res = await client.request(method, url, timeout=TIMEOUT_S, follow_redirects=False, headers=headers, json=json)
        try:
            body = res.json()
        except ValueError:
            body = res.text
        return ReqResult(ok=True, status=res.status_code, body=body)
    except Exception as err:  # noqa: BLE001
        return ReqResult(ok=False, error=type(err).__name__)


def _rand() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=7))


def _get_path(obj: Any, path: str) -> Any:
    cur = obj
    for k in path.split("."):
        if cur is None:
            return None
        cur = cur.get(k) if isinstance(cur, dict) else None
    return cur


async def run_active_probes(target: dict) -> list[Finding]:
    auth = target.get("auth")
    if not auth:
        return []
    base = (target.get("baseUrl") or "").rstrip("/")
    scheme = auth.get("scheme", "Bearer ")
    token_field = auth.get("tokenField", "token")
    out: list[Finding] = []
    provided = target.get("_credentials") or []

    def bearer(token: str) -> dict:
        return {"Authorization": scheme + token}

    def login_body(u: str, p: str) -> dict:
        tpl = auth.get("loginBody")
        if isinstance(tpl, dict) and tpl:
            return {k: (v.replace("{username}", u).replace("{password}", p) if isinstance(v, str) else v) for k, v in tpl.items()}
        return {"username": u, "password": p}

    async with httpx.AsyncClient() as client:

        async def login_provided(cred: dict) -> dict:
            login = await _req(client, base + auth["login"], method="POST", json=login_body(cred["username"], cred["password"]))
            token = None
            if login.ok and isinstance(login.body, dict):
                token = _get_path(login.body, token_field) or login.body.get(token_field) or login.body.get("token") or login.body.get("auth_token")
            return {"u": cred["username"], "p": cred["password"], "reg": ReqResult(ok=True, status=200), "login": login,
                    "token": token, "role": cred.get("role", "user"), "resourceId": cred.get("resourceId")}

        async def make_user(extra: dict | None = None) -> dict:
            u = "sx_" + _rand()
            p = "Pw!" + _rand() + "9"
            reg = await _req(client, base + auth["register"], method="POST",
                              json={"username": u, "password": p, "email": f"{u}@sentinela.test", **(extra or {})})
            login = await _req(client, base + auth["login"], method="POST", json={"username": u, "password": p})
            token = None
            if login.ok and isinstance(login.body, dict):
                token = login.body.get(token_field) or login.body.get("token") or login.body.get("auth_token")
            return {"u": u, "p": p, "reg": reg, "login": login, "token": token}

        provided_users = [await login_provided(c) for c in provided] if auth.get("login") and provided else []
        can_register = bool(auth.get("register"))
        probe = provided_users[0] if provided_users else (await make_user() if can_register else None)
        if probe is None or not probe["reg"].ok or not probe["token"]:
            out.append(finding(
                id="D-AUTH-00", category="TOKEN_SESSION", status=STATUS.SKIP, severity="INFO", source="dynamic",
                title="Probes ativos pulados (fluxo de auth indisponível)",
                detail=(f"Não consegui logar em {base} com as credenciais de teste cadastradas — confira usuário, senha e rota de login."
                        if provided_users else f"Não consegui registrar/logar em {base} para os testes ativos."),
            ))
            return out

        # ---------- API2: JWT — alg=none, segredo fraco, claim exp ----------
        decoded = decode_jwt(probe["token"])
        if decoded:
            alg = decoded["header"].get("alg", "?")

            forged = forge_alg_none(probe["token"])
            forged_accepted = None
            if forged and auth.get("protectedProbe"):
                r = await _req(client, base + auth["protectedProbe"], headers=bearer(forged))
                forged_accepted = r.ok and r.status == 200
            out.append(finding(
                id="D-JWT-01", category="TOKEN_SESSION", severity="CRITICAL", owasp="API2:2023", source="dynamic",
                title="JWT — alg=none não é aceito",
                status=(STATUS.SKIP if forged_accepted is None
                        else STATUS.FAIL if forged_accepted else STATUS.PASS),
                detail=(f"Token usa alg={alg}; não testei aceitação de alg=none (sem protectedProbe configurado)."
                        if forged_accepted is None
                        else "Um token reassinado com alg=none (sem assinatura) foi ACEITO pela rota protegida — qualquer claim pode ser forjado."
                        if forged_accepted
                        else "Um token com alg=none foi corretamente rejeitado."),
                recommendation="Nunca honrar o alg vindo do header do token; fixar o algoritmo esperado (allowlist) na verificação.",
                evidence=f"alg original: {alg}",
            ))

            weak = find_weak_hmac_secret(probe["token"])
            out.append(finding(
                id="D-JWT-02", category="TOKEN_SESSION", severity="CRITICAL", owasp="API2:2023", source="dynamic",
                title="JWT — segredo HMAC não é trivial",
                status=STATUS.SKIP if alg not in ("HS256", "HS384", "HS512") else STATUS.FAIL if weak else STATUS.PASS,
                detail=(f"Algoritmo {alg} não é HMAC — verificação de segredo fraco não se aplica." if alg not in ("HS256", "HS384", "HS512")
                        else f'Segredo "{weak}" (lista de segredos comuns) reproduz a assinatura — qualquer um pode forjar tokens.' if weak
                        else "Nenhum segredo da wordlist testada reproduziu a assinatura."),
                recommendation="Usar um segredo aleatório de alto entropia (≥32 bytes) ou migrar para chave assimétrica (RS256/ES256).",
                evidence=f"alg: {alg}",
            ))

            has_exp = "exp" in decoded["payload"]
            out.append(finding(
                id="D-JWT-03", category="TOKEN_SESSION", severity="MEDIUM", owasp="API2:2023", source="dynamic",
                title="JWT possui claim de expiração (exp)",
                status=STATUS.PASS if has_exp else STATUS.WARN,
                detail="Token traz exp — expira." if has_exp else "Token não tem claim exp — pode não expirar nunca.",
                recommendation="Todo token de acesso deve ter TTL curto via claim exp.",
            ))

        # ---------- API3: exposição de dados sensíveis na resposta ----------
        if auth.get("protectedProbe"):
            me_valid = await _req(client, base + auth["protectedProbe"], headers=bearer(probe["token"]))
            hits = _find_sensitive_keys(me_valid.body) if me_valid.ok and isinstance(me_valid.body, dict) else []
            out.append(finding(
                id="D-EXPOSE-01", category="INPUT_VALIDATION", severity="HIGH", owasp="API3:2023", source="dynamic",
                title="Resposta não expõe campos sensíveis",
                status=STATUS.SKIP if not me_valid.ok else STATUS.FAIL if hits else STATUS.PASS,
                detail=(f"Falha ao requisitar {auth['protectedProbe']}." if not me_valid.ok
                        else f"Campo(s) potencialmente sensíveis na resposta: {', '.join(hits)}." if hits
                        else "Nenhum campo da lista de sensíveis (senha, chave, documento...) apareceu na resposta."),
                recommendation="Usar allowlist de campos na serialização da resposta (nunca serializar o model inteiro).",
                evidence=(f"GET {base}{auth['protectedProbe']} (autenticado)\n→ campos sensíveis na resposta: {', '.join(hits)}" if hits else ""),
            ))

        # ---------- API2: autenticação exigida e token validado ----------
        if auth.get("protectedProbe"):
            no_tok = await _req(client, base + auth["protectedProbe"])
            bad_tok = await _req(client, base + auth["protectedProbe"], headers=bearer("nao.e.um.token.valido"))

            def rejects(r: ReqResult) -> bool:
                return r.ok and r.status in (401, 403)

            both = rejects(no_tok) and rejects(bad_tok)
            out.append(finding(
                id="D-AUTH-01", category="TOKEN_SESSION", severity="HIGH", owasp="API2:2023", source="dynamic",
                title="Rota protegida exige token válido",
                status=(STATUS.SKIP if not no_tok.ok or not bad_tok.ok else STATUS.PASS if both else STATUS.FAIL),
                detail=(f"Falha ao requisitar {auth['protectedProbe']}." if not no_tok.ok or not bad_tok.ok
                        else f"{auth['protectedProbe']} negou acesso sem token ({no_tok.status}) e com token inválido ({bad_tok.status})." if both
                        else f"{auth['protectedProbe']} respondeu sem token={no_tok.status}, com token inválido={bad_tok.status} — deveria negar (401)."),
                recommendation="Exigir token assinado e válido em toda rota protegida; rejeitar ausência e tokens malformados.",
                evidence=f"GET {base}{auth['protectedProbe']}\n→ sem token: HTTP {no_tok.status or '-'} · token inválido: HTTP {bad_tok.status or '-'}",
            ))

        # ---------- API1: BOLA dinâmico (dois usuários) ----------
        if target.get("bola"):
            if len(provided_users) >= 2:
                non_admin = [u for u in provided_users if u["role"] != "admin"]
                attacker = non_admin[0] if non_admin else provided_users[1]
                victim = next(u for u in provided_users if u is not attacker)
            elif can_register:
                victim = await make_user()
                attacker = await make_user()
            else:
                victim = attacker = {"token": None, "u": None}
            if not attacker["token"] or not victim["u"]:
                out.append(finding(
                    id="D-BOLA-01", category="AUTHORIZATION", status=STATUS.SKIP, severity="INFO", source="dynamic",
                    title="BOLA dinâmico pulado",
                    detail="Não consegui preparar dois usuários de teste — cadastre 2 credenciais no projeto ou informe a rota de cadastro.",
                ))
            else:
                bola_cfg = target["bola"]
                path = bola_cfg["path"].replace("{victimId}", str(victim.get("resourceId") or victim["u"])).replace("{victim}", victim["u"])
                r = await _req(client, base + path, method=bola_cfg.get("method", "PUT"),
                                headers=bearer(attacker["token"]), json=bola_cfg.get("body"))
                success = r.ok and 200 <= r.status < 300
                out.append(finding(
                    id="D-BOLA-01", category="AUTHORIZATION", severity="CRITICAL", owasp="API1:2023", source="dynamic",
                    title="BOLA dinâmico — agir sobre o objeto de outro usuário",
                    status=STATUS.SKIP if not r.ok else STATUS.FAIL if success else STATUS.PASS,
                    detail=("Falha ao requisitar." if not r.ok
                            else f"O usuário \"{attacker['u']}\" executou {bola_cfg.get('method', 'PUT')} {path} sobre o recurso de \"{victim['u']}\" e recebeu {r.status} — BOLA confirmado (acessou objeto alheio)." if success
                            else f"Tentativa de \"{attacker['u']}\" agir sobre o recurso de \"{victim['u']}\" foi negada ({r.status})."),
                    recommendation="Validar que o dono do token é o dono do objeto antes de qualquer leitura/escrita.",
                    evidence=(f"{bola_cfg.get('method', 'PUT')} {base}{path}\n"
                              f"(autenticado como \"{attacker['u']}\"; o recurso pertence a \"{victim['u']}\")\n→ HTTP {r.status or '-'}"),
                ))

        # ---------- API5: BFLA (usuário comum em função administrativa) ----------
        bfla_routes = target.get("bfla") or []
        if bfla_routes:
            common = next((u for u in provided_users if u["role"] != "admin" and u["token"]), None)
            if common is None and can_register:
                common = await make_user()
                common["role"] = "user"
            for i, route in enumerate(bfla_routes):
                method = str(route.get("method", "GET")).upper()
                url = base + route["path"]
                fid = f"D-BFLA-0{i + 1}"
                title = f"BFLA — usuário comum negado em {method} {route['path']}"
                if not common or not common.get("token"):
                    out.append(finding(
                        id=fid, category="AUTHORIZATION", severity="HIGH", owasp="API5:2023", source="dynamic",
                        status=STATUS.SKIP, title=title,
                        detail="Sem usuário de papel comum para testar — cadastre uma credencial com papel diferente de admin.",
                    ))
                    continue
                r = await _req(client, url, method=method, headers=bearer(common["token"]), json=route.get("body"))
                allowed = r.ok and 200 <= r.status < 300
                out.append(finding(
                    id=fid, category="AUTHORIZATION", severity="HIGH", owasp="API5:2023", source="dynamic", title=title,
                    status=STATUS.SKIP if not r.ok else STATUS.FAIL if allowed else STATUS.PASS,
                    detail=("Falha ao requisitar." if not r.ok
                            else f'O usuário "{common["u"]}" (papel "{common.get("role", "user")}") acessou a função administrativa e recebeu {r.status} — BFLA confirmado.' if allowed
                            else f'Usuário comum foi negado ({r.status}) na função administrativa.'),
                    recommendation="Validar o papel/permissão do usuário no servidor em toda rota administrativa (deny by default).",
                    evidence=f'{method} {url}\n(autenticado como "{common["u"]}", papel "{common.get("role", "user")}")\n→ HTTP {r.status or "-"}',
                ))

        # ---------- API3: mass assignment (campo privilegiado) ----------
        mass = target.get("massAssignment")
        if mass and mass.get("field") and can_register:
            field = mass["field"]
            mu = await make_user({field: True})
            escalated = False
            detail = ""
            if mu["token"] and auth.get("protectedProbe"):
                me = await _req(client, base + auth["protectedProbe"], headers=bearer(mu["token"]))
                val = _get_path(me.body, mass.get("verifyMePath", f"data.{field}")) if me.ok else None
                escalated = val is True
                detail = (f'Registrei com "{field}": true e o próprio usuário voltou como {field}=true — escalonamento de privilégio via payload!'
                          if escalated else f'Campo "{field}" enviado no registro não foi persistido ({field}={val}).')
            else:
                detail = "Não consegui verificar via rota protegida."
            out.append(finding(
                id="D-MASS-01", category="INPUT_VALIDATION", severity="HIGH", owasp="API3:2023", source="dynamic",
                title="Mass assignment — atribuição de campo privilegiado",
                status=STATUS.SKIP if not mu["reg"].ok else STATUS.FAIL if escalated else STATUS.PASS,
                detail=detail,
                recommendation="Nunca aceitar campos sensíveis (admin/role/isAdmin) direto do payload; usar allowlist de campos no bind.",
                evidence=f"{field} escalou" if escalated else "sem escalonamento",
            ))

    return out
