# Análise estática GENÉRICA (independe de framework): varre o código-fonte em
# várias linguagens por más práticas comuns — segredos no código, TLS
# desligado, modo debug, hash fraco, SQL concatenado, CORS aberto, JWT sem
# verificação. As verificações específicas de Next.js ficam em static_analyzer.

import os
import re
from dataclasses import dataclass

from .models import STATUS, Finding, finding

EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".java", ".kt", ".go", ".cs", ".php", ".rb",
    ".yml", ".yaml", ".properties", ".env", ".conf", ".ini", ".toml", ".config", ".xml",
}
IGNORE_DIRS = {"node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__", ".venv", "venv", "coverage", ".next", "bin", "obj"}
MAX_FILE_BYTES = 400_000
MAX_FILES = 4000
TEST_HINT = re.compile(r"(^|/)(tests?|__tests__|spec|mocks?|fixtures?|examples?)(/|$)|\.(test|spec)\.", re.I)


@dataclass
class Hit:
    file: str
    line: int
    snippet: str


def detect_stack(root: str | None) -> str:
    """'nextjs' quando as verificações específicas de Next.js fazem sentido."""
    if not root or not os.path.isdir(root):
        return "unknown"
    pkg = os.path.join(root, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                if '"next"' in fh.read():
                    return "nextjs"
        except OSError:
            pass
    return "generic"


def _walk(root: str):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in EXTENSIONS and name not in (".env", ".env.example"):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            n += 1
            if n > MAX_FILES:
                return
            yield os.path.relpath(full, root).replace("\\", "/"), text


# (id, título, severidade, regex, recomendação, ignorar_testes)
RULES = [
    ("S-SEC-01", "Sem segredos fixos no código", "CRITICAL",
     re.compile(r"""(?ix)
        (?:AKIA[0-9A-Z]{16}                                   # AWS access key
        |-----BEGIN\ (?:RSA\ |EC\ |OPENSSH\ )?PRIVATE\ KEY-----
        |gh[pousr]_[A-Za-z0-9]{30,}                            # token GitHub
        |xox[baprs]-[A-Za-z0-9-]{10,}                          # token Slack
        |AIza[0-9A-Za-z_\-]{35}                                # chave Google
        |(?:password|passwd|senha|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\s$\{<>]{8,}["'])
     """),
     "Mover segredos para variáveis de ambiente/cofre (Vault, Secrets Manager), rotacionar os já expostos e nunca versionar credenciais.", True),
    ("S-SEC-02", "Verificação de certificado TLS não está desligada", "HIGH",
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER", re.I),
     "Manter a validação de certificado ligada; para CAs internas, instalar a CA no trust store em vez de desligar a verificação.", True),
    ("S-SEC-03", "Modo debug não está ativo", "MEDIUM",
     re.compile(r"\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1|spring\.devtools", re.I),
     "Desativar debug em produção — ele expõe stack traces, console interativo e variáveis internas.", True),
    ("S-SEC-04", "Hash de senha/segredo não usa algoritmo fraco", "HIGH",
     re.compile(r"(?:md5|sha1)\s*\(.{0,40}(?:pass|senha|pwd)|hashlib\.(?:md5|sha1)\(.{0,60}(?:pass|senha|pwd)|MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-?1)[\"']\s*\)|createHash\(\s*['\"](?:md5|sha1)['\"]\s*\)", re.I),
     "Usar bcrypt, scrypt ou Argon2 (com salt) para senhas; MD5/SHA-1 são quebráveis por força bruta.", True),
    ("S-SEC-05", "Consultas SQL não são montadas por concatenação", "HIGH",
     re.compile(r"""(?ix)
        (?:execute|query|raw|prepareStatement|createQuery|executeQuery)\s*\(\s*
        (?:f["']\s*(?:select|insert|update|delete)\b[^"']*\{
          |["']\s*(?:select|insert|update|delete)\b[^"']*["']\s*(?:\+|%\s*\(|\.format\()
          |`\s*(?:select|insert|update|delete)\b[^`]*\$\{)
     """),
     "Usar consultas parametrizadas/prepared statements ou o ORM — nunca concatenar entrada do usuário em SQL (injeção).", True),
    ("S-SEC-06", "CORS não libera qualquer origem", "MEDIUM",
     re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']|Access-Control-Allow-Origin['\"]?\s*[:,=]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|AllowAnyOrigin\(\)|CORS\(\s*app\s*\)|addAllowedOrigin\(\s*[\"']\*[\"']", re.I),
     "Trocar o curinga (*) por uma lista explícita de origens confiáveis, principalmente quando há cookies/credenciais.", True),
    ("S-SEC-07", "Tokens JWT são sempre verificados", "HIGH",
     re.compile(r"verify_signature['\"]?\s*[:=]\s*False|jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|ignoreExpiration\s*:\s*true", re.I),
     "Sempre verificar assinatura e expiração do JWT e fixar a lista de algoritmos aceitos (nunca 'none').", True),
]


def run_generic_static(target: dict) -> list[Finding]:
    root = target.get("projectPath")
    if not root or not os.path.isdir(root):
        return []

    hits: dict[str, list[Hit]] = {r[0]: [] for r in RULES}
    scanned = 0
    for rel, text in _walk(root):
        scanned += 1
        in_tests = bool(TEST_HINT.search(rel))
        for rid, _title, _sev, rx, _rec, skip_tests in RULES:
            if in_tests and skip_tests:
                continue
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                snippet = text[m.start():m.start() + 90].splitlines()[0]
                if rid == "S-SEC-01":
                    snippet = re.sub(r"([\"'])[^\"']{4,}([\"'])", r"\1[REDACTED]\2", snippet)  # nunca copiar o segredo
                    snippet = re.sub(r"(AKIA|gh[pousr]_|xox[baprs]-|AIza)[A-Za-z0-9_\-]+", r"\1[REDACTED]", snippet)
                hits[rid].append(Hit(rel, line, snippet.strip()))
                if len(hits[rid]) >= 25:
                    break

    out: list[Finding] = []
    for rid, title, sev, _rx, rec, _skip in RULES:
        h = hits[rid]
        if h:
            top = h[:5]
            out.append(finding(
                id=rid, category="INPUT_VALIDATION" if rid == "S-SEC-05" else "TRANSPORT" if rid == "S-SEC-02" else "TOKEN_SESSION",
                severity=sev, source="static", title=title, status=STATUS.FAIL,
                detail=f"{len(h)} ocorrência(s) em {len({x.file for x in h})} arquivo(s). Ex.: {top[0].file}:{top[0].line}.",
                recommendation=rec,
                evidence="\n".join(f"{x.file}:{x.line}  {x.snippet}" for x in top),
            ))
        else:
            out.append(finding(
                id=rid, category="INPUT_VALIDATION" if rid == "S-SEC-05" else "TRANSPORT" if rid == "S-SEC-02" else "TOKEN_SESSION",
                severity=sev, source="static", title=title, status=STATUS.PASS,
                detail=f"Nenhuma ocorrência em {scanned} arquivo(s) analisado(s).", recommendation=rec,
            ))
    return out
