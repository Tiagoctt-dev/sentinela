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
from .active_probes import SENSITIVE_KEYS, _find_sensitive_keys, _rand
from .dynamic_analyzer import _redact
from .endpoint_discovery import SPEC_PATHS
from .models import STATUS, Finding, finding

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

    async def login(u: str, p: str, role: str):
        try:
            res = await client.post(base + auth["login"], json=_login_body(auth, u, p), timeout=TIMEOUT_S)
            body = res.json()
        except Exception:  # noqa: BLE001
            return
        token = body.get(field_name) or body.get("token") or body.get("auth_token") if isinstance(body, dict) else None
        if token:
            users.append({"u": u, "role": role, "headers": {"Authorization": scheme + token}})

    creds = target.get("_credentials") or []
    if creds:
        for c in creds:
            await login(c["username"], c["password"], c.get("role", "user"))
    elif auth.get("register"):
        u, p = "sx_" + _rand(), "Pw!" + _rand() + "9"
        try:
            await client.post(base + auth["register"], json={"username": u, "password": p, "email": f"{u}@sentinela.test"}, timeout=TIMEOUT_S)
        except Exception:  # noqa: BLE001
            return users
        await login(u, p, "user")
    return users


def _f(fid: str, cat: str, sev: str, owasp: str, title: str, status: str, detail: str, rec: str, evidence: str = "", data: Any = None) -> Finding:
    return finding(id=fid, category=cat, severity=sev, owasp=owasp, source="dynamic", title=title, status=status,
                   detail=detail, recommendation=rec, evidence=evidence, data=data)


def _line(method: str, url: str, res) -> str:
    return f"{method} {url} → HTTP {res.status_code}"


async def run_spec_checks(target: dict) -> list[Finding]:
    base = (target.get("baseUrl") or "").rstrip("/")
    out: list[Finding] = []
    auth = target.get("auth") or {}

    async with httpx.AsyncClient() as client:
        spec_url, spec = await load_spec(client, target, base)
        ops = parse_operations(spec) if spec else []
        all_gets = [o for o in ops if o.method == "GET" and not o.has_path_params]
        skipped_unsafe = [o.path for o in all_gets if o.unsafe]
        gets = [o for o in all_gets if not o.unsafe][:MAX_OPS]
        users = await _tokens(client, target, base)
        common = next((u for u in users if u["role"] != "admin"), None)

        # ---- API2: rotas que a spec declara protegidas devem negar acesso anônimo
        secured = [o for o in gets if o.secured]
        if not spec:
            out.append(_f("D-SPEC-01", "AUTHORIZATION", "HIGH", "API2:2023", "Rotas protegidas pela spec negam acesso anônimo",
                          STATUS.SKIP, "Spec OpenAPI/Swagger não encontrada — informe a URL da spec no projeto para testar todas as rotas.",
                          "Publique/forneça a spec OpenAPI para habilitar o teste automático de todas as rotas."))
        elif not secured:
            out.append(_f("D-SPEC-01", "AUTHORIZATION", "HIGH", "API2:2023", "Rotas protegidas pela spec negam acesso anônimo",
                          STATUS.SKIP, f"Spec em {spec_url}: nenhuma rota GET com 'security' declarado para testar.",
                          "Declare 'security' nas operações protegidas da spec para que possam ser verificadas."))
        else:
            leaks = []
            for o in secured:
                res = await _get(client, base + o.path)
                if res is not None and 200 <= res.status_code < 300:
                    leaks.append(_line("GET", base + o.path, res))
            out.append(_f("D-SPEC-01", "AUTHORIZATION", "HIGH", "API2:2023", "Rotas protegidas pela spec negam acesso anônimo",
                          STATUS.FAIL if leaks else STATUS.PASS,
                          (f"{len(leaks)} de {len(secured)} rota(s) declaradas protegidas responderam 2xx sem credencial." if leaks
                           else f"{len(secured)} rota(s) protegidas testadas sem credencial; todas negaram."),
                          "Aplicar autenticação obrigatória no servidor (deny by default) — a spec diz que a rota é protegida, mas ela não é.",
                          "\n".join(leaks[:6])))

        # ---- API3: dados sensíveis servidos sem autenticação
        exposed = []
        for o in [x for x in gets if not x.secured]:
            res = await _get(client, base + o.path)
            if res is None or not (200 <= res.status_code < 300) or "json" not in res.headers.get("content-type", ""):
                continue
            try:
                hits = _find_sensitive_keys(res.json())
            except ValueError:
                continue
            if hits:
                body = _redact(" ".join(res.text[:280].split()))
                exposed.append(f"{_line('GET', base + o.path, res)}\n   campos sensíveis: {', '.join(sorted(set(hits))[:5])}\n   {body}")
        if gets:
            out.append(_f("D-SPEC-02", "INPUT_VALIDATION", "CRITICAL", "API3:2023", "Rotas públicas não expõem dados sensíveis",
                          STATUS.FAIL if exposed else STATUS.PASS,
                          (f"{len(exposed)} rota(s) sem autenticação devolvem campos sensíveis." if exposed
                           else f"{len([x for x in gets if not x.secured])} rota(s) públicas testadas; nenhuma devolveu campos sensíveis.")
                          + (f" Por segurança, {len(skipped_unsafe)} rota(s) com nome de ação não foram chamadas: {', '.join(skipped_unsafe[:4])}." if skipped_unsafe else ""),
                          "Exigir autenticação nessas rotas e devolver só campos necessários (allowlist de serialização); remover endpoints de debug.",
                          "\n".join(exposed[:3])))

        # ---- API5: BFLA automático (rotas administrativas com usuário comum)
        admin_ops = [o for o in gets if ADMIN_PATH.search(o.path) or any("admin" in t for t in o.tags)]
        if admin_ops:
            if not common:
                out.append(_f("D-BFLA-A1", "AUTHORIZATION", "HIGH", "API5:2023", "BFLA automático — rotas administrativas negam usuário comum",
                              STATUS.SKIP, f"{len(admin_ops)} rota(s) administrativas na spec, mas sem usuário comum para testar (cadastre credenciais em Acesso).",
                              "Cadastre um usuário de papel comum no projeto para liberar este teste."))
            else:
                allowed = []
                for o in admin_ops:
                    res = await _get(client, base + o.path, headers=common["headers"])
                    if res is not None and 200 <= res.status_code < 300:
                        allowed.append(_line("GET", base + o.path, res))
                out.append(_f("D-BFLA-A1", "AUTHORIZATION", "HIGH", "API5:2023", "BFLA automático — rotas administrativas negam usuário comum",
                              STATUS.FAIL if allowed else STATUS.PASS,
                              (f'O usuário comum "{common["u"]}" acessou {len(allowed)} de {len(admin_ops)} rota(s) administrativas.' if allowed
                               else f"{len(admin_ops)} rota(s) administrativas negaram o usuário comum."),
                              "Validar papel/permissão no servidor em toda função administrativa (deny by default).",
                              "\n".join(allowed[:6])))

        # ---- API6: fluxos sensíveis sem proteção anti-automação documentada
        flows = [o for o in ops if o.method in ("POST", "PUT", "PATCH") and SENSITIVE_FLOW.search(o.path)]
        if flows:
            unprotected = [o for o in flows if "429" not in o.response_codes]
            out.append(_f("D-FLOW-01", "AUTHORIZATION", "MEDIUM", "API6:2023", "Fluxos de negócio sensíveis têm limite anti-automação documentado",
                          STATUS.WARN if unprotected else STATUS.PASS,
                          (f"{len(unprotected)} de {len(flows)} fluxo(s) sensíveis não documentam resposta 429 / limite de uso." if unprotected
                           else f"{len(flows)} fluxo(s) sensíveis documentam limite de uso (429)."),
                          "Aplicar rate limit/quotas e proteção anti-automação (CAPTCHA, device binding, limites por conta) nos fluxos de transferência, cadastro, OTP e reset.",
                          "\n".join(f"{o.method} {o.path}" for o in unprotected[:8])))

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
            if len(codes) >= 8:
                out.append(_f("D-FLOW-02", "TOKEN_SESSION", "MEDIUM", "API6:2023", "Login protegido contra força bruta",
                              STATUS.PASS if throttled else STATUS.WARN,
                              ("O login passou a limitar/bloquear tentativas repetidas." if throttled
                               else f"{len(codes)} tentativas de login inválidas seguidas não foram limitadas (sem 429/423/Retry-After)."),
                              "Limitar tentativas por IP/conta, aplicar atraso progressivo/bloqueio temporário e alertar sobre credential stuffing.",
                              f"POST {base}{auth['login']} × {len(codes)} (usuário inexistente)\n→ HTTP {sorted(set(codes))}"))

        # ---- API7: SSRF por callback (canário hospedado pelo próprio Sentinela)
        ssrf_ops = [(o, [q for q in o.query_params if SSRF_PARAM.search(q)]) for o in gets]
        ssrf_ops = [(o, qs) for o, qs in ssrf_ops if qs]
        if ssrf_ops:
            confirmed, tested = [], 0
            headers = common["headers"] if common else (users[0]["headers"] if users else None)
            for o, qs in ssrf_ops[:12]:
                for q in qs[:2]:
                    token = canary.new_token()
                    await _get(client, base + o.path, headers=headers, params={q: canary.url_for(token)})
                    tested += 1
                    await asyncio.sleep(0.6)
                    if canary.was_hit(token):
                        confirmed.append(f"GET {base}{o.path}?{q}=<url do Sentinela>\n→ o servidor buscou a URL informada (callback recebido)")
            out.append(_f("D-SSRF-01", "INPUT_VALIDATION", "CRITICAL", "API7:2023", "Parâmetros de URL não permitem SSRF",
                          STATUS.FAIL if confirmed else STATUS.PASS,
                          (f"SSRF confirmado em {len(confirmed)} parâmetro(s): o servidor fez uma requisição a um endereço controlado pelo Sentinela." if confirmed
                           else f"{tested} parâmetro(s) de URL testados com um endereço-canário; o servidor não fez requisições a ele "
                                f"(o alvo precisa alcançar {canary.public_base()} para o teste ser conclusivo)."),
                          "Validar URLs recebidas com allowlist de hosts, bloquear IPs internos/metadata (169.254.169.254, RFC1918) e desligar redirecionamentos.",
                          "\n".join(confirmed[:4])))

        # ---- API8/API9: rotas de debug/administração acessíveis
        found = []
        for path, kind in EXPOSED_PATHS:
            res = await _get(client, base + path)
            if res is None or res.status_code != 200:
                continue
            ctype, text = res.headers.get("content-type", ""), res.text[:400]
            ok = (kind == "env" and re.search(r"^[A-Z][A-Z0-9_]+=", text, re.M)) or \
                 (kind == "git" and "[core]" in text) or \
                 (kind == "actuator" and ("_links" in text or "propertySources" in text or "json" in ctype)) or \
                 (kind == "any" and "html" not in ctype and len(text) > 20)
            if ok:
                found.append(_line("GET", base + path, res))
        out.append(_f("D-EXPO-01", "HEADERS", "HIGH", "API9:2023", "Rotas de debug/administração não estão expostas",
                      STATUS.FAIL if found else STATUS.PASS,
                      (f"{len(found)} rota(s) sensíveis acessíveis sem autenticação." if found
                       else f"{len(EXPOSED_PATHS)} caminhos comuns de debug/administração testados; nenhum acessível."),
                      "Remover ou restringir (rede interna/autenticação forte) endpoints de actuator, debug, métricas e arquivos de configuração.",
                      "\n".join(found[:5])))

    return out
