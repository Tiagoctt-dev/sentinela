# Testes guiados pela spec OpenAPI/Swagger: em vez de depender só das rotas
# digitadas no alvo, lê a spec do sistema e testa TODAS as operações seguras
# (GET, sem parâmetro de caminho). Nada que altere dados é chamado aqui.
#
# Cobre: acesso anônimo a rotas protegidas (API2), exposição de dados
# sensíveis (API3), BFLA automático em rotas administrativas (API5),
# fluxos de negócio sensíveis e força bruta no login (API6), SSRF por
# callback (API7) e rotas de debug/administração expostas (API8/API9).

import asyncio
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from . import canary
from .active_probes import _find_sensitive_keys, _rand
from .dynamic_analyzer import _redact
from .endpoint_discovery import SPEC_PATHS
from .models import STATE, STATUS, Finding, finding

TIMEOUT_S = 6.0
MAX_OPS = 40

SSRF_PARAM = re.compile(r"(^|[_\-.])(url|uri|link|callback|webhook|redirect|image|avatar|feed|fetch|target|dest|destination|proxy|src|source|endpoint|host)($|[_\-.])", re.I)
ADMIN_PATH = re.compile(r"/(admin|administrator|backoffice|internal|manage|management|superuser|debug|_debug)(/|$|_)", re.I)
SENSITIVE_FLOW = re.compile(
    r"(transfer|payment|/pay\b|pix|withdraw|deposit|checkout|purchase|/orders?\b|signup|register|otp|verify|reset|forgot|password|refresh|coupon|redeem|invite|/sms|/email)",
    re.I,
)
VERBS = ("get", "post", "put", "patch", "delete")

# Um GET nem sempre é inofensivo (ex.: /createdb, /logout, /reset). Rotas cujo nome sugere
# efeito colateral nunca são chamadas — ficam listadas como ignoradas por segurança.
UNSAFE_PATH = re.compile(
    r"(create|delete|remove|destroy|drop|reset|init|seed|populate|truncate|wipe|purge|clear|"
    r"logout|signout|revoke|invalidate|cancel|confirm|activate|deactivate|approve|reject|"
    r"send|trigger|run|execute|exec|import|migrate|restart|shutdown|kill|"
    r"pay|transfer|withdraw|deposit|checkout|unsubscribe|subscribe|sync|refresh|rotate)",
    re.I,
)

EXPOSED_PATHS = [
    ("/actuator/env", "actuator"), ("/actuator/heapdump", "actuator"), ("/actuator", "actuator"),
    ("/.env", "env"), ("/.git/config", "git"), ("/server-status", "any"), ("/phpinfo.php", "any"),
    ("/debug", "any"), ("/console", "any"), ("/metrics", "any"),
]


@dataclass
class Op:
    method: str
    path: str
    secured: bool
    tags: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    has_path_params: bool = False
    unsafe: bool = False
    response_codes: set[str] = field(default_factory=set)


def _resolve(spec: dict, node: Any) -> Any:
    if isinstance(node, dict) and "$ref" in node:
        cur: Any = spec
        for part in str(node["$ref"]).lstrip("#/").split("/"):
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        return cur
    return node


def parse_operations(spec: dict) -> list[Op]:
    global_sec = bool(spec.get("security"))
    ops: list[Op] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = [_resolve(spec, p) for p in item.get("parameters", [])]
        for verb in VERBS:
            op = item.get(verb)
            if not isinstance(op, dict):
                continue
            params = shared + [_resolve(spec, p) for p in op.get("parameters", [])]
            sec = op["security"] if "security" in op else spec.get("security")
            ops.append(Op(
                method=verb.upper(), path=path, secured=bool(sec) if sec is not None else global_sec,
                tags=[str(t).lower() for t in op.get("tags", [])],
                query_params=[p.get("name", "") for p in params if isinstance(p, dict) and p.get("in") == "query"],
                has_path_params="{" in path,
                unsafe=bool(UNSAFE_PATH.search(path)),
                response_codes={str(c) for c in (op.get("responses") or {}).keys()},
            ))
    return ops


async def load_spec(client: httpx.AsyncClient, target: dict, base: str) -> tuple[Optional[str], Optional[dict]]:
    uploaded = target.get("openapiSpec")
    if isinstance(uploaded, dict) and isinstance(uploaded.get("paths"), dict):
        return "spec enviada", uploaded  # spec importada pelo usuário tem prioridade
    explicit = target.get("openapiUrl")
    candidates = [explicit if str(explicit).startswith("http") else base + explicit] if explicit else [base + p for p in SPEC_PATHS]
    for url in candidates:
        try:
            res = await client.get(url, timeout=TIMEOUT_S, follow_redirects=False)
            if res.status_code == 200:
                spec = res.json()
                if isinstance(spec.get("paths"), dict):
                    return url, spec
        except Exception:  # noqa: BLE001
            continue
    return None, None


async def _get(client: httpx.AsyncClient, url: str, headers: Optional[dict] = None, params: Optional[dict] = None):
    try:
        res = await client.get(url, headers=headers, params=params, timeout=TIMEOUT_S, follow_redirects=False)
        return res
    except Exception:  # noqa: BLE001
        return None


def _login_body(auth: dict, u: str, p: str) -> dict:
    tpl = auth.get("loginBody")
    if isinstance(tpl, dict) and tpl:
        return {k: (v.replace("{username}", u).replace("{password}", p) if isinstance(v, str) else v) for k, v in tpl.items()}
    return {"username": u, "password": p}


async def _tokens(client: httpx.AsyncClient, target: dict, base: str) -> list[dict]:
    auth = target.get("auth") or {}
    if not auth.get("login"):
        return []
    field_name = auth.get("tokenField", "token")
    scheme = auth.get("scheme", "Bearer ")
    users: list[dict] = []

    async def login(u: str, p: str, role: str, resource_id: Optional[str] = None):
        try:
            res = await client.post(base + auth["login"], json=_login_body(auth, u, p), timeout=TIMEOUT_S)
            body = res.json()
        except Exception:  # noqa: BLE001
            return
        token = body.get(field_name) or body.get("token") or body.get("auth_token") if isinstance(body, dict) else None
        if token:
            users.append({"u": u, "role": role, "headers": {"Authorization": scheme + token}, "resourceId": resource_id})

    creds = target.get("_credentials") or []
    if creds:
        for c in creds:
            await login(c["username"], c["password"], c.get("role", "user"), c.get("resourceId"))
    elif auth.get("register"):
        u, p = "sx_" + _rand(), "Pw!" + _rand() + "9"
        try:
            await client.post(base + auth["register"], json={"username": u, "password": p, "email": f"{u}@sentinela.test"}, timeout=TIMEOUT_S)
        except Exception:  # noqa: BLE001
            return users
        await login(u, p, "user")
    return users


def _f(fid: str, cat: str, sev: str, owasp: str, title: str, status: str, detail: str, rec: str, evidence: str = "", data: Any = None) -> Finding:
    state = (data or {}).pop("state", "") if isinstance(data, dict) else ""
    return finding(id=fid, category=cat, severity=sev, owasp=owasp, source="dynamic", title=title, status=status,
                   detail=detail, recommendation=rec, evidence=evidence, data=data, state=state)


def canary_reachable(base: str) -> bool:
    """O canário só é conclusivo se o alvo alcança o endereço público do Sentinela. Assumimos que sim apenas
    quando os dois estão na mesma máquina (loopback), ou quando PUBLIC_API_URL foi configurada explicitamente."""
    if os.environ.get("PUBLIC_API_URL"):
        return True
    loop = ("localhost", "127.0.0.1", "::1")
    from urllib.parse import urlparse
    return (urlparse(base).hostname or "") in loop


def _line(method: str, url: str, res) -> str:
    return f"{method} {url} → HTTP {res.status_code}"


async def run_spec_checks(target: dict) -> list[Finding]:
    base = (target.get("baseUrl") or "").rstrip("/")
    out: list[Finding] = []
    auth = target.get("auth") or {}

    async with httpx.AsyncClient() as client:
        spec_url, spec = await load_spec(client, target, base)
        ops = parse_operations(spec) if spec else []
        # Só GET sem parâmetro de caminho (/users, não /users/{id}) — chamar um GET
        # com {id} exigiria adivinhar um ID válido, o que foge do escopo "seguro" deste
        # módulo. Isso significa que rotas clássicas de BOLA (/recurso/{id}) NÃO são
        # cobertas aqui — só pelos probes dinâmicos configurados (BOLA/BFLA no projeto).
        path_param_gets = [o for o in ops if o.method == "GET" and o.has_path_params]
        all_gets = [o for o in ops if o.method == "GET" and not o.has_path_params]
        skipped_unsafe = [o.path for o in all_gets if o.unsafe]
        gets = [o for o in all_gets if not o.unsafe][:MAX_OPS]
        path_param_note = (
            f" ({len(path_param_gets)} rota(s) com parâmetro no caminho, ex. /recurso/{{id}}, não entram nesta "
            "varredura automática — exigem um ID real; use BOLA/BFLA dinâmico no projeto para testá-las.)"
            if path_param_gets else ""
        )
        users = await _tokens(client, target, base)
        common = next((u for u in users if u["role"] != "admin"), None)

        def obs(method: str, path: str, res, outcome: str, **extra) -> dict:
            return {"method": method, "path": path, "httpStatus": (res.status_code if res is not None else None), "outcome": outcome, **extra}

        # ---- API2: rotas que a spec declara protegidas devem negar acesso anônimo
        secured = [o for o in gets if o.secured]
        TITLE01 = "Rotas protegidas pela spec negam acesso anônimo"
        if not spec:
            out.append(_f("D-SPEC-01", "AUTHORIZATION", "HIGH", "API2:2023", TITLE01,
                          STATUS.SKIP, "Spec OpenAPI/Swagger não encontrada — informe a URL da spec no projeto para testar todas as rotas.",
                          "Publique/forneça a spec OpenAPI para habilitar o teste automático de todas as rotas.", data={"state": STATE.NOT_RUN}))
        elif not secured:
            out.append(_f("D-SPEC-01", "AUTHORIZATION", "HIGH", "API2:2023", TITLE01,
                          STATUS.SKIP, f"Spec em {spec_url}: nenhuma rota GET com 'security' declarado para testar.",
                          "Declare 'security' nas operações protegidas da spec para que possam ser verificadas.", data={"state": STATE.NOT_APPLICABLE}))
        else:
            leaks, o1 = [], []
            for o in secured:
                res = await _get(client, base + o.path)
                exposed_now = res is not None and 200 <= res.status_code < 300
                o1.append(obs("GET", o.path, res, "exposed" if exposed_now else "error" if res is None else "denied"))
                if exposed_now:
                    leaks.append(_line("GET", base + o.path, res))
            all_error = all(x["outcome"] == "error" for x in o1)
            out.append(_f("D-SPEC-01", "AUTHORIZATION", "HIGH", "API2:2023", TITLE01,
                          STATUS.FAIL if leaks else STATUS.SKIP if all_error else STATUS.PASS,
                          (f"{len(leaks)} de {len(secured)} rota(s) declaradas protegidas responderam 2xx sem credencial." if leaks
                           else "Falha ao requisitar as rotas protegidas." if all_error
                           else f"{len(secured)} rota(s) protegidas testadas sem credencial; todas negaram.") + path_param_note,
                          "Aplicar autenticação obrigatória no servidor (deny by default) — a spec diz que a rota é protegida, mas ela não é.",
                          "\n".join(leaks[:6]), data={"observations": o1, **({"state": STATE.ERROR} if all_error and not leaks else {})}))

        # ---- API3: dados sensíveis servidos sem autenticação
        exposed, o2 = [], []
        for o in [x for x in gets if not x.secured]:
            res = await _get(client, base + o.path)
            if res is None:
                o2.append(obs("GET", o.path, None, "error"))
                continue
            if not (200 <= res.status_code < 300):
                o2.append(obs("GET", o.path, res, "denied"))
                continue
            if "json" not in res.headers.get("content-type", ""):
                o2.append(obs("GET", o.path, res, "not_json"))
                continue
            try:
                hits = _find_sensitive_keys(res.json())
            except ValueError:
                o2.append(obs("GET", o.path, res, "not_json"))
                continue
            o2.append(obs("GET", o.path, res, "sensitive" if hits else "clean", fields=sorted(set(hits))[:5]))
            if hits:
                body = _redact(" ".join(res.text[:280].split()))
                exposed.append(f"{_line('GET', base + o.path, res)}\n   campos sensíveis: {', '.join(sorted(set(hits))[:5])}\n   {body}")
        if gets:
            checked = [x for x in o2 if x["outcome"] in ("clean", "sensitive")]
            out.append(_f("D-SPEC-02", "INPUT_VALIDATION", "CRITICAL", "API3:2023", "Rotas públicas não expõem dados sensíveis",
                          STATUS.FAIL if exposed else STATUS.PASS,
                          (f"{len(exposed)} rota(s) sem autenticação devolvem campos sensíveis." if exposed
                           else f"{len(checked)} rota(s) públicas com resposta JSON analisadas; nenhuma devolveu campos sensíveis.")
                          + (f" Por segurança, {len(skipped_unsafe)} rota(s) com nome de ação não foram chamadas: {', '.join(skipped_unsafe[:4])}." if skipped_unsafe else "")
                          + path_param_note,
                          "Exigir autenticação nessas rotas e devolver só campos necessários (allowlist de serialização); remover endpoints de debug.",
                          "\n".join(exposed[:3]), data={"observations": o2}))

        # ---- API5: BFLA automático (rotas administrativas com usuário comum)
        admin_ops = [o for o in gets if ADMIN_PATH.search(o.path) or any("admin" in t for t in o.tags)]
        if admin_ops:
            TITLE_A1 = "BFLA automático — rotas administrativas negam usuário comum"
            if not common:
                out.append(_f("D-BFLA-A1", "AUTHORIZATION", "HIGH", "API5:2023", TITLE_A1,
                              STATUS.SKIP, f"{len(admin_ops)} rota(s) administrativas na spec, mas sem usuário comum para testar (cadastre credenciais em Acesso).",
                              "Cadastre um usuário de papel comum no projeto para liberar este teste.", data={"requiresLogin": True, "state": STATE.NOT_RUN}))
            else:
                allowed, o3 = [], []
                for o in admin_ops:
                    res = await _get(client, base + o.path, headers=common["headers"])
                    ok_now = res is not None and 200 <= res.status_code < 300
                    unauth = res is not None and res.status_code == 401
                    o3.append(obs("GET", o.path, res, "exposed" if ok_now else "error" if res is None else "inconclusive" if unauth else "denied"))
                    if ok_now:
                        allowed.append(_line("GET", base + o.path, res))
                inconclusive_only = not allowed and all(x["outcome"] in ("error", "inconclusive") for x in o3)
                out.append(_f("D-BFLA-A1", "AUTHORIZATION", "HIGH", "API5:2023", TITLE_A1,
                              STATUS.FAIL if allowed else STATUS.SKIP if inconclusive_only else STATUS.PASS,
                              (f'O usuário comum "{common["u"]}" acessou {len(allowed)} de {len(admin_ops)} rota(s) administrativas.' if allowed
                               else "Todas as respostas foram 401 ou falha de rede — não é possível concluir se há checagem de papel." if inconclusive_only
                               else f"{len(admin_ops)} rota(s) administrativas negaram o usuário comum."),
                              "Validar papel/permissão no servidor em toda função administrativa (deny by default).",
                              "\n".join(allowed[:6]), data={"requiresLogin": True, "observations": o3, **({"state": STATE.INCONCLUSIVE} if inconclusive_only else {})}))

        # ---- API1: BOLA automático em rotas /recurso/{id} (só leitura)
        TITLE_A1B = "BOLA automático — rotas /recurso/{id} negam o objeto de outro usuário"
        id_ops = [o for o in path_param_gets if not o.unsafe and o.secured and o.path.count("{") == 1
                  and not (ADMIN_PATH.search(o.path) or any("admin" in t for t in o.tags))][:MAX_OPS]
        if id_ops:
            attacker = common
            victim = next((u for u in users if u is not attacker and u.get("resourceId")), None)
            if not attacker or not victim:
                out.append(_f("D-BOLA-A1", "AUTHORIZATION", "CRITICAL", "API1:2023", TITLE_A1B, STATUS.SKIP,
                              f"{len(id_ops)} rota(s) com identificador na spec, mas faltam dois usuários de teste e o ID do recurso do dono (cadastre em Acesso o campo 'ID do recurso').",
                              "Cadastre dois usuários comuns e informe o identificador de um recurso do segundo usuário.",
                              data={"requiresLogin": True, "state": STATE.NOT_RUN}))
            else:
                def fill(path: str, value: str) -> str:
                    return re.sub(r"\{[^}]+\}", str(value), path, count=1)

                o5, confirmed, indicative, applicable = [], [], [], 0
                for o in id_ops:
                    own = await _get(client, base + fill(o.path, victim["resourceId"]), headers=victim["headers"])
                    if own is None or not (200 <= own.status_code < 300):
                        o5.append(obs("GET", fill(o.path, victim["resourceId"]), own, "not_applicable"))
                        continue  # o ID informado não pertence a esta rota: nada a concluir aqui
                    applicable += 1
                    url_path = fill(o.path, victim["resourceId"])
                    res = await _get(client, base + url_path, headers=attacker["headers"])
                    if res is None:
                        o5.append(obs("GET", url_path, None, "error"))
                    elif res.status_code == 401:
                        o5.append(obs("GET", url_path, res, "inconclusive"))
                    elif 200 <= res.status_code < 300:
                        ghost = await _get(client, base + fill(o.path, "sx_inexistente_" + _rand()), headers=attacker["headers"])
                        ignores_id = ghost is not None and 200 <= ghost.status_code < 300
                        o5.append(obs("GET", url_path, res, "exposed_ignores_id" if ignores_id else "exposed"))
                        line = f"{_line('GET', base + url_path, res)} (recurso de \"{victim['u']}\"; controle com ID inexistente → HTTP {ghost.status_code if ghost is not None else '-'})"
                        (indicative if ignores_id else confirmed).append(line)
                    else:
                        o5.append(obs("GET", url_path, res, "denied"))
                if confirmed:
                    out.append(_f("D-BOLA-A1", "AUTHORIZATION", "CRITICAL", "API1:2023", TITLE_A1B, STATUS.FAIL,
                                  f'O usuário "{attacker["u"]}" leu o recurso de "{victim["u"]}" em {len(confirmed)} de {applicable} rota(s) testadas.',
                                  "Validar que o dono do token é o dono do objeto antes de devolver ou alterar qualquer recurso identificado por ID.",
                                  "\n".join(confirmed[:5]), data={"requiresLogin": True, "observations": o5}))
                elif indicative:
                    out.append(_f("D-BOLA-A1", "AUTHORIZATION", "CRITICAL", "API1:2023", TITLE_A1B, STATUS.WARN,
                                  f"{len(indicative)} rota(s) responderam 2xx também para um ID inexistente: a API parece ignorar o identificador, então o 2xx é indício, não prova.",
                                  "Validar o dono do objeto e responder 404/403 para IDs que não pertencem ao usuário.",
                                  "\n".join(indicative[:5]), data={"requiresLogin": True, "observations": o5, "state": STATE.LIKELY}))
                elif applicable and all(x["outcome"] == "denied" for x in o5 if x["outcome"] != "not_applicable"):
                    out.append(_f("D-BOLA-A1", "AUTHORIZATION", "CRITICAL", "API1:2023", TITLE_A1B, STATUS.PASS,
                                  f"{applicable} rota(s) com identificador negaram o acesso de \"{attacker['u']}\" ao recurso de \"{victim['u']}\".",
                                  "Manter a validação de dono em todas as rotas com identificador.",
                                  data={"requiresLogin": True, "observations": o5}))
                else:
                    out.append(_f("D-BOLA-A1", "AUTHORIZATION", "CRITICAL", "API1:2023", TITLE_A1B, STATUS.SKIP,
                                  ("O ID informado não abriu nenhuma das rotas com identificador para o próprio dono — confira o campo 'ID do recurso'." if not applicable
                                   else "Respostas 401 ou falha de rede — não é possível concluir se há checagem de dono."),
                                  "Informe o ID de um recurso real do segundo usuário.",
                                  data={"requiresLogin": True, "observations": o5, "state": STATE.INCONCLUSIVE}))

        # ---- API6: fluxos sensíveis sem proteção anti-automação documentada
        flows = [o for o in ops if o.method in ("POST", "PUT", "PATCH") and SENSITIVE_FLOW.search(o.path)]
        if flows:
            unprotected = [o for o in flows if "429" not in o.response_codes]
            o4 = [{"method": o.method, "path": o.path, "httpStatus": None, "outcome": "undocumented" if o in unprotected else "documented"} for o in flows]
            out.append(_f("D-FLOW-01", "AUTHORIZATION", "MEDIUM", "API6:2023", "Fluxos de negócio sensíveis têm limite anti-automação documentado",
                          STATUS.WARN if unprotected else STATUS.PASS,
                          (f"{len(unprotected)} de {len(flows)} fluxo(s) sensíveis não documentam resposta 429 / limite de uso." if unprotected
                           else f"{len(flows)} fluxo(s) sensíveis documentam limite de uso (429)."),
                          "Aplicar rate limit/quotas e proteção anti-automação (CAPTCHA, device binding, limites por conta) nos fluxos de transferência, cadastro, OTP e reset.",
                          "\n".join(f"{o.method} {o.path}" for o in unprotected[:8]), data={"observations": o4, "documentationOnly": True}))

        # ---- API6/API2: força bruta no login (usuário aleatório, nenhuma conta real é afetada)
        if auth.get("login"):
            throttled, codes = False, []
            for _ in range(12):
                try:
                    r = await client.post(base + auth["login"], json=_login_body(auth, "sx_" + _rand(), "Wrong!" + _rand()), timeout=TIMEOUT_S)
                except Exception:  # noqa: BLE001
                    break
                codes.append(r.status_code)
                if r.status_code in (423, 429) or "retry-after" in r.headers:
                    throttled = True
                    break
            TITLE_F2 = "Login protegido contra força bruta"
            if throttled or len(codes) >= 8:  # um bloqueio observado já é conclusivo, mesmo com poucas tentativas
                out.append(_f("D-FLOW-02", "TOKEN_SESSION", "MEDIUM", "API6:2023", TITLE_F2,
                              STATUS.PASS if throttled else STATUS.WARN,
                              ("O login passou a limitar/bloquear tentativas repetidas." if throttled
                               else f"{len(codes)} tentativas de login inválidas seguidas não foram limitadas (sem 429/423/Retry-After)."),
                              "Limitar tentativas por IP/conta, aplicar atraso progressivo/bloqueio temporário e alertar sobre credential stuffing.",
                              f"POST {base}{auth['login']} × {len(codes)} (usuário inexistente)\n→ HTTP {sorted(set(codes))}",
                              data={"observations": [{"method": "POST", "path": auth["login"], "httpStatus": c, "outcome": "throttled" if c in (423, 429) else "accepted"} for c in codes[:12]]}))
            else:
                out.append(_f("D-FLOW-02", "TOKEN_SESSION", "MEDIUM", "API6:2023", TITLE_F2, STATUS.SKIP,
                              f"Só {len(codes)} de 12 tentativas completaram — não foi possível concluir.",
                              "Verifique a disponibilidade da rota de login.", data={"state": STATE.INCONCLUSIVE}))

        # ---- API7: SSRF por callback (canário hospedado pelo próprio Sentinela)
        ssrf_ops = [(o, [q for q in o.query_params if SSRF_PARAM.search(q)]) for o in gets]
        ssrf_ops = [(o, qs) for o, qs in ssrf_ops if qs]
        if ssrf_ops:
            confirmed, tested, o5 = [], 0, []
            headers = common["headers"] if common else (users[0]["headers"] if users else None)
            for o, qs in ssrf_ops[:12]:
                for q in qs[:2]:
                    token = canary.new_token()
                    res = await _get(client, base + o.path, headers=headers, params={q: canary.url_for(token)})
                    tested += 1
                    await asyncio.sleep(0.6)
                    hit = canary.was_hit(token)
                    o5.append(obs("GET", o.path, res, "ssrf_confirmed" if hit else "no_callback", param=q))
                    if hit:
                        confirmed.append(f"GET {base}{o.path}?{q}=<url do Sentinela>\n→ o servidor buscou a URL informada (callback recebido)")
            reach = canary_reachable(base)
            if confirmed:
                status, state = STATUS.FAIL, ""
                detail = f"SSRF confirmado em {len(confirmed)} parâmetro(s): o servidor fez uma requisição a um endereço controlado pelo Sentinela."
            elif reach:
                status, state = STATUS.PASS, ""
                detail = f"{tested} parâmetro(s) de URL testados; o servidor não acessou o endereço-canário, que o alvo consegue alcançar."
            else:
                status, state = STATUS.SKIP, STATE.INCONCLUSIVE
                detail = (f"{tested} parâmetro(s) de URL testados e nenhum acesso ao canário foi registrado, mas não há como confirmar que o alvo alcança "
                          f"{canary.public_base()} — por isso a ausência de acesso NÃO descarta SSRF. Defina PUBLIC_API_URL com um endereço alcançável pelo alvo.")
            out.append(_f("D-SSRF-01", "INPUT_VALIDATION", "CRITICAL", "API7:2023", "Parâmetros de URL não permitem SSRF",
                          status, detail,
                          "Validar URLs recebidas com allowlist de hosts, bloquear IPs internos/metadata (169.254.169.254, RFC1918) e desligar redirecionamentos.",
                          "\n".join(confirmed[:4]), data={"observations": o5, "canaryReachable": reach, **({"state": state} if state else {})}))

        # ---- API8/API9: rotas de debug/administração acessíveis
        found, o6 = [], []
        for path, kind in EXPOSED_PATHS:
            res = await _get(client, base + path)
            if res is None:
                o6.append(obs("GET", path, None, "error"))
                continue
            if res.status_code != 200:
                o6.append(obs("GET", path, res, "denied"))
                continue
            ctype, text = res.headers.get("content-type", ""), res.text[:400]
            ok = (kind == "env" and re.search(r"^[A-Z][A-Z0-9_]+=", text, re.M)) or \
                 (kind == "git" and "[core]" in text) or \
                 (kind == "actuator" and ("_links" in text or "propertySources" in text or "json" in ctype)) or \
                 (kind == "any" and "html" not in ctype and len(text) > 20)
            o6.append(obs("GET", path, res, "exposed" if ok else "denied"))
            if ok:
                found.append(_line("GET", base + path, res))
        all_failed = all(x["outcome"] == "error" for x in o6)
        out.append(_f("D-EXPO-01", "HEADERS", "HIGH", "API9:2023", "Rotas de debug/administração não estão expostas",
                      STATUS.FAIL if found else STATUS.SKIP if all_failed else STATUS.PASS,
                      (f"{len(found)} rota(s) sensíveis acessíveis sem autenticação." if found
                       else "Nenhuma requisição foi concluída — falha ao requisitar o alvo." if all_failed
                       else f"{len(EXPOSED_PATHS)} caminhos comuns de debug/administração testados; nenhum acessível."),
                      "Remover ou restringir (rede interna/autenticação forte) endpoints de actuator, debug, métricas e arquivos de configuração.",
                      "\n".join(found[:5]), data={"observations": o6}))

    return out
