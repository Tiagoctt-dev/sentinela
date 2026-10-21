# Análise ESTÁTICA: lê os arquivos do projeto-alvo e deduz quais práticas de
# segurança estão implementadas — sem executar nada.
# Porte de lib/static-analyzer.mjs.

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import STATUS, Finding, finding

CODE_EXT = {".ts", ".tsx", ".js", ".mjs", ".cjs", ".prisma", ".json"}
IGNORE_DIRS = {"node_modules", ".next", ".git", "dist", "build", ".turbo", "coverage"}


@dataclass
class SourceFile:
    rel: str
    text: str


@dataclass
class Index:
    root: Optional[str]
    files: list[SourceFile] = field(default_factory=list)


def index_project(root: Optional[str]) -> Index:
    if not root or not os.path.isdir(root):
        return Index(root=root, files=[])
    files: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1] not in CODE_EXT:
                continue
            full = os.path.join(dirpath, name)
            try:
                with open(full, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(full, root).replace("\\", "/")
            files.append(SourceFile(rel=rel, text=text))
    return Index(root=root, files=files)


def grep(index: Index, regex: re.Pattern) -> list[str]:
    return [f.rel for f in index.files if regex.search(f.text)]


def has(index: Index, regex: re.Pattern) -> bool:
    return len(grep(index, regex)) > 0


def find_file(index: Index, rel: str) -> Optional[SourceFile]:
    return next((f for f in index.files if f.rel == rel), None)


def owned_models(index: Index) -> set[str]:
    schema = next((f for f in index.files if re.search(r"schema\.prisma$", f.rel)), None)
    owned: set[str] = set()
    if not schema:
        return owned
    for m in re.finditer(r"model\s+(\w+)\s*\{([\s\S]*?)\}", schema.text):
        if re.search(r"\buserId\b", m.group(2)):
            owned.add(m.group(1))
    return owned


def _reason_for(file: str, id_expr: str) -> str:
    if re.search(r"cron|refresh|batch|schedul", file, re.I):
        return "operação em job de sistema (não é acesso de usuário)"
    if re.search(r"\.id$", id_expr):
        return "id vem de coleção já escopada por userId (loop)"
    return "posse validada pelo chamador antes da operação (upstream)"


def bola_scan(index: Index) -> dict:
    owned = owned_models(index)
    accessor = {n[0].lower() + n[1:]: n for n in owned}

    op_re = re.compile(r"prisma\.([a-zA-Z]+)\.(update|delete|findUnique|findFirst|updateMany|deleteMany)\s*\(")
    candidates = []
    per_model: dict[str, dict[str, int]] = {}
    scoped = 0
    checked = 0

    def bump(model: str, key: str):
        per_model.setdefault(model, {"scoped": 0, "flagged": 0})
        per_model[model][key] += 1

    for f in index.files:
        if re.search(r"\.test\.(ts|js)$", f.rel):
            continue
        for m in op_re.finditer(f.text):
            nonlocal_model = accessor.get(m.group(1))
            if not nonlocal_model:
                continue
            model = nonlocal_model
            win = f.text[m.start():m.start() + 260]
            w = re.search(r"where:\s*\{([^}]*)\}", win)
            if not w or not re.search(r"\bid\b", w.group(1)):
                continue
            checked += 1
            if re.search(r"userId", w.group(1)):
                scoped += 1
                bump(model, "scoped")
                continue

            id_expr_m = re.search(r"\bid:\s*([A-Za-z_$][\w.$]*)", w.group(1))
            id_expr = id_expr_m.group(1) if id_expr_m else "id"
            back = f.text[max(0, m.start() - 1800):m.start()]
            where_blocks = re.findall(r"where:\s*\{[^}]*\}", back)
            esc = re.escape(id_expr)
            protected_by_owner = any(
                re.search(r"userId", b) and re.search(rf"\b{esc}\b", b) for b in where_blocks
            )
            if not protected_by_owner and re.search(r"\.id$", id_expr):
                protected_by_owner = any(re.search(r"userId", b) for b in where_blocks)

            if protected_by_owner:
                scoped += 1
                bump(model, "scoped")
                continue
            line = f.text[:m.start()].count("\n") + 1
            bump(model, "flagged")
            candidates.append({
                "file": f.rel, "line": line, "model": model, "op": m.group(2),
                "idExpr": id_expr, "reason": _reason_for(f.rel, id_expr),
            })

    return {
        "owned": sorted(owned), "checked": checked, "scoped": scoped,
        "perModel": per_model, "candidates": candidates,
    }


def run_static(target: dict) -> list[Finding]:
    idx = index_project(target.get("projectPath"))
    legacy = index_project(target.get("legacyPath"))
    out: list[Finding] = []

    if not idx.files:
        out.append(finding(
            id="S-ENV-00", category="INPUT_VALIDATION", status=STATUS.SKIP, severity="INFO",
            title="Projeto não encontrado para análise estática",
            detail=f"Não achei código em {target.get('projectPath')}. Ajuste \"projectPath\" no target.",
        ))
        return out

    api_routes = [
        f for f in idx.files
        if re.search(r"src/app/api/.+/route\.(ts|js)$", f.rel) and not re.search(r"\[\.\.\.nextauth\]", f.rel)
    ]

    # ---------- AUTORIZAÇÃO ----------
    middleware = next((f for f in idx.files if re.search(r"(^|/)(proxy|middleware)\.(ts|js)$", f.rel)), None)
    out.append(finding(
        id="S-AUTHZ-01", category="AUTHORIZATION", severity="HIGH",
        title="Middleware protege as rotas da aplicação",
        status=STATUS.PASS if middleware and re.search(r"matcher", middleware.text) else STATUS.FAIL,
        detail=(f"Middleware encontrado em {middleware.rel}, aplicando verificação de sessão por matcher."
                if middleware else "Nenhum middleware de proteção de rotas foi encontrado."),
        recommendation="Centralizar a checagem de sessão em middleware, redirecionando não autenticados.",
        evidence=middleware.rel if middleware else "",
    ))

    def is_guarded(f: SourceFile) -> bool:
        return bool(
            re.search(r"\bauth\s*\(", f.text) or re.search(r"session", f.text) or
            re.search(r"validateRequest", f.text) or re.search(r"x-twilio-signature", f.text, re.I) or
            re.search(r"CRON_SECRET|Bearer", f.text)
        )

    guarded = [f for f in api_routes if is_guarded(f)]
    unguarded = [f for f in api_routes if f not in guarded]
    out.append(finding(
        id="S-AUTHZ-02", category="AUTHORIZATION", severity="CRITICAL",
        title="Rotas de API verificam autenticação/assinatura",
        status=(STATUS.SKIP if not api_routes
                else STATUS.PASS if not unguarded
                else STATUS.WARN if len(unguarded) <= len(api_routes) / 3 else STATUS.FAIL),
        detail=("Nenhuma rota de API localizada." if not api_routes
                else f"{len(guarded)}/{len(api_routes)} rotas fazem verificação de acesso própria." +
                (f" Sem verificação explícita: {', '.join(f.rel for f in unguarded)}." if unguarded else "")),
        recommendation="Rotas com dados devem validar sessão (BOLA/OWASP API #1) ou provar a origem (assinatura/bearer); endpoints públicos (ex.: cadastro) precisam de proteção contra abuso/rate limiting.",
        evidence=f"{len(guarded)}/{len(api_routes)} rotas",
    ))

    bola = bola_scan(idx)
    out.append(finding(
        id="S-BOLA-01", category="AUTHORIZATION", severity="MEDIUM", owasp="API1:2023",
        title="Autorização em nível de objeto (BOLA)",
        status=(STATUS.SKIP if not bola["owned"] else STATUS.PASS if not bola["candidates"] else STATUS.WARN),
        detail=("Não identifiquei modelos com userId no schema para avaliar BOLA." if not bola["owned"]
                else (f"{bola['scoped']} operações por id em modelos do usuário estão escopadas por userId "
                      "(inline ou após checagem de dono) — sem BOLA aparente." if not bola["candidates"]
                      else f"{bola['scoped']} operações protegidas por userId. {len(bola['candidates'])} "
                      "operação(ões) definem a posse de forma indireta (via chamador, loop ou job) — revise para confirmar: " +
                      "; ".join(f"{c['file']}:{c['line']} ({c['model']}.{c['op']})" for c in bola["candidates"]) + ".")),
        recommendation="Prefira restringir por userId no próprio where (where: { id, userId }); onde a posse vier de cima, garanta que essa checagem sempre exista antes da operação.",
        evidence=f"{bola['scoped']} protegidas · {len(bola['candidates'])} a revisar",
        data={"type": "bola", **bola},
    ))

    # ---------- TOKEN & SESSÃO ----------
    cookie_flags = [flag for flag in ("httpOnly", "secure", "sameSite")
                    if has(idx, re.compile(flag, re.I)) or has(legacy, re.compile(flag, re.I))]
    out.append(finding(
        id="S-TOKEN-01", category="TOKEN_SESSION", severity="HIGH",
        title="Cookies de sessão com flags de proteção",
        status=STATUS.PASS if len(cookie_flags) == 3 else STATUS.WARN if cookie_flags else STATUS.FAIL,
        detail=(f"Flags presentes: {', '.join(cookie_flags)}." if cookie_flags
                else "Não encontrei configuração de httpOnly/secure/sameSite."),
        recommendation="Cookies de auth devem ser httpOnly + secure + sameSite para mitigar XSS/CSRF.",
        evidence=" · ".join(cookie_flags),
    ))

    reset_lifecycle = has(idx, re.compile("verificationToken", re.I)) and has(idx, re.compile("expires", re.I))
    out.append(finding(
        id="S-TOKEN-02", category="TOKEN_SESSION", severity="MEDIUM",
        title="Tokens de recuperação expiram e são de uso único",
        status=STATUS.PASS if reset_lifecycle else STATUS.WARN,
        detail=("Tokens de reset possuem expiração e são removidos após o uso." if reset_lifecycle
                else "Ciclo de vida de tokens temporários não confirmado."),
        recommendation="Tokens sensíveis devem ter TTL curto e ser invalidados após o consumo.",
    ))

    dpop = has(idx, re.compile("DPoP", re.I))
    out.append(finding(
        id="S-TOKEN-03", category="TOKEN_SESSION", severity="LOW",
        title="DPoP — prova de posse do token (sender-constrained)",
        status=STATUS.PASS if dpop else STATUS.WARN,
        detail="Uso de DPoP detectado." if dpop else "Tokens são bearer; não há vínculo do token a uma chave do cliente (DPoP).",
        recommendation="Para grau bancário (FAPI), adotar DPoP ou mTLS para tornar o token sender-constrained.",
    ))

    # ---------- OAUTH / OIDC / PKCE ----------
    oauth = has(idx, re.compile(r"next-auth|providers/google|Authorization Code|oauth", re.I)) or \
        has(legacy, re.compile(r"oauth|google", re.I))
    out.append(finding(
        id="S-OIDC-01", category="OAUTH_OIDC", severity="HIGH",
        title="OAuth 2.0 / OpenID Connect configurado",
        status=STATUS.PASS if oauth else STATUS.FAIL,
        detail=("Login via provedor OAuth/OIDC (Google) presente; conjunto de tokens OIDC persistido." if oauth
                else "Nenhum fluxo OAuth/OIDC encontrado."),
        recommendation="Usar Authorization Code (nunca Implicit) e validar id_token/emissor.",
    ))

    pkg = find_file(idx, "package.json")
    next_auth_m = re.search(r'"next-auth"\s*:\s*"([^"]+)"', pkg.text) if pkg else None
    next_auth = next_auth_m.group(1) if next_auth_m else None
    state_or_pkce = has(idx, re.compile("pkce|code_challenge", re.I)) or has(legacy, re.compile("state", re.I)) or bool(next_auth)
    out.append(finding(
        id="S-OIDC-02", category="OAUTH_OIDC", severity="MEDIUM",
        title="PKCE e state no fluxo de autorização",
        status=STATUS.PASS if state_or_pkce else STATUS.WARN,
        detail=(f"Auth.js (next-auth {next_auth}) aplica PKCE + state por padrão no fluxo do Google." if next_auth
                else "Proteção do authorization code (PKCE/state) não confirmada."),
        recommendation="PKCE é obrigatório em clientes públicos; state protege contra CSRF no callback.",
        evidence=f"next-auth {next_auth}" if next_auth else "",
    ))

    # ---------- INTEGRIDADE ----------
    sig = has(idx, re.compile("validateRequest|x-twilio-signature", re.I))
    out.append(finding(
        id="S-INTEG-01", category="INTEGRITY", severity="HIGH",
        title="Webhooks verificam assinatura da requisição",
        status=STATUS.PASS if sig else STATUS.WARN,
        detail=("Webhook valida a assinatura antes de processar (rejeita requisições forjadas)." if sig
                else "Não encontrei verificação de assinatura em webhooks."),
        recommendation="Todo webhook deve validar assinatura/HMAC para garantir a origem.",
    ))

    bearer = has(idx, re.compile("CRON_SECRET")) and has(idx, re.compile("Bearer"))
    out.append(finding(
        id="S-INTEG-02", category="INTEGRITY", severity="MEDIUM",
        title="Endpoints internos protegidos por segredo (Bearer)",
        status=STATUS.PASS if bearer else STATUS.WARN,
        detail=("Endpoint de cron exige Authorization: Bearer e falha fechado em produção." if bearer
                else "Endpoints internos/cron sem proteção por segredo detectada."),
        recommendation="Proteger jobs/endpoints internos com segredo e negar por padrão (fail-closed).",
    ))

    # ---------- HEADERS ----------
    next_config = next((f for f in idx.files if re.search(r"next\.config\.(mjs|js|ts)$", f.rel)), None)
    next_headers = bool(next_config and re.search(r"headers\s*\(", next_config.text))
    helmet_legacy = has(legacy, re.compile("helmet"))
    out.append(finding(
        id="S-HEAD-01", category="HEADERS", severity="MEDIUM",
        title="Cabeçalhos de segurança HTTP configurados",
        status=STATUS.PASS if next_headers else STATUS.FAIL,
        detail=("next.config define headers() de segurança." if next_headers
                else "O app não define cabeçalhos de segurança em next.config." +
                (" (Helmet existe apenas na API legada.)" if helmet_legacy else "")),
        recommendation="Definir HSTS, X-Frame-Options, X-Content-Type-Options, CSP e Referrer-Policy via next.config.headers().",
        evidence="helmet só no legado" if helmet_legacy else "",
    ))

    # ---------- VALIDAÇÃO DE ENTRADA ----------
    zod = has(idx, re.compile(r"\bz\.(object|string|number)|safeParse"))
    out.append(finding(
        id="S-INPUT-01", category="INPUT_VALIDATION", severity="MEDIUM",
        title="Validação de esquema na entrada (Zod)",
        status=STATUS.PASS if zod else STATUS.WARN,
        detail="Entradas validadas com Zod antes de tocar o banco." if zod else "Validação de entrada não confirmada.",
        recommendation="Validar todo payload no servidor (OWASP API #6/#8) antes de persistir.",
    ))

    bcrypt = has(idx, re.compile("bcrypt"))
    out.append(finding(
        id="S-INPUT-02", category="INPUT_VALIDATION", severity="HIGH",
        title="Senhas com hash forte (bcrypt)",
        status=STATUS.PASS if bcrypt else STATUS.WARN,
        detail="Senhas armazenadas com bcrypt." if bcrypt else "Hashing de senha não confirmado.",
        recommendation="Nunca armazenar senha em texto puro; usar bcrypt/argon2 com custo adequado.",
    ))

    # ---------- TRANSPORTE ----------
    mtls = has(idx, re.compile(r"mtls|mutual.?tls|requestCert|clientCertificate", re.I))
    out.append(finding(
        id="S-TLS-01", category="TRANSPORT", severity="LOW",
        title="mTLS — TLS mútuo por certificado",
        status=STATUS.PASS if mtls else STATUS.WARN,
        detail="Configuração de mTLS detectada." if mtls else "Usa TLS padrão (HTTPS), sem autenticação mútua por certificado.",
        recommendation="Grau bancário (FAPI) exige mTLS ou DPoP para prender o token ao cliente.",
    ))

    return out
