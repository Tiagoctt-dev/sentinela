"""Alvo de laboratório para os testes: uma API HTTP local (só 127.0.0.1) cujo comportamento é
configurável. Permite validar cada verificação contra uma versão VULNERÁVEL, uma SEGURA e
variantes que provocam falsos positivos/negativos conhecidos.
"""

import base64
import hashlib
import hmac
import json
import threading
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SECRET = "x9!k2-segredo-longo-e-aleatorio-do-laboratorio"
PASSWORD = "Senha#123"
USERS = {"ana": "user", "bruno": "user", "root": "admin"}


@dataclass
class Behavior:
    # autenticação
    accept_alg_none: bool = False          # JWT alg=none aceito
    weak_secret: bool = False              # assina com "secret"
    protected_is_public: bool = False      # /me responde 200 sem credencial (rota realmente pública)
    # autorização
    bola_vulnerable: bool = False          # PUT /users/{u}/email sem checar dono
    bola_ignores_id: bool = False          # PUT aceita qualquer id (2xx até para inexistentes)
    always_401_on_put: bool = False        # recusa qualquer token com 401
    bfla_vulnerable: bool = False          # /admin/* aberto a usuário comum
    bfla_returns_401: bool = False         # /admin/* responde 401 ao usuário comum
    bola_path: str = ""                    # "" | "vulnerable" | "secure" — GET /api/contas/{id} na spec
    # exposição
    leak_public: bool = False              # /publico/clientes devolve CPF/senha
    leak_env: bool = False                 # /.env acessível
    spec_marks_secured_but_open: bool = False  # /api/contas diz protegida mas responde 200
    ssrf_vulnerable: bool = False          # /api/preview?url= busca a URL
    mass_assign_vulnerable: bool = False   # POST /register aceita {"admin": true}
    leak_me: bool = False                  # /me devolve campo sensível
    # tokens
    jwt_no_exp: bool = False               # tokens sem claim exp
    # integridade
    webhook_unsigned: bool = False         # POST /webhook aceita sem assinatura
    cron_open: bool = False                # GET /cron responde sem segredo
    login_rate_limit: bool = False         # POST /login passa a responder 429 após 5 falhas
    has_providers: bool = False            # GET /auth/providers
    wsdl: str = ""                         # "" | "plain" | "secured" — serviço SOAP em /service?wsdl
    # configuração
    leak_server_header: bool = False       # Server: Werkzeug/2.2.3 Python/3.11
    security_headers: bool = True
    rate_limit: bool = False               # 429 após 5 requisições à raiz
    # estado
    calls: list = field(default_factory=list)
    hits: int = 0
    reg_users: dict = field(default_factory=dict)
    failed_logins: int = 0


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_jwt(user: str, secret: str, with_exp: bool = True) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"sub": user}
    if with_exp:
        payload["exp"] = 4102444800
    body = _b64(json.dumps(payload).encode())
    sig = _b64(hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def spec_for(b: Behavior) -> dict:
    return {
        "openapi": "3.0.0", "info": {"title": "lab", "version": "1"},
        "paths": {
            "/api/contas": {"get": {"security": [{"bearer": []}], "responses": {"200": {}}}},
            "/api/preview": {"get": {"parameters": [{"name": "url", "in": "query"}], "responses": {"200": {}}}},
            **({"/api/contas/{id}": {"get": {"security": [{"bearer": []}], "responses": {"200": {}}}}} if b.bola_path else {}),
            "/admin/usuarios": {"get": {"tags": ["admin"], "security": [{"bearer": []}], "responses": {"200": {}}}},
            "/publico/clientes": {"get": {"responses": {"200": {}}}},
            "/api/transferencias": {"post": {"security": [{"bearer": []}], "responses": {"201": {}}}},
            "/createdb": {"get": {"responses": {"200": {}}}},
        },
    }


def build_handler(b: Behavior):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self):
            return "Werkzeug/2.2.3 Python/3.11.1" if b.leak_server_header else "lab"

        def log_message(self, *a):
            pass

        def _send(self, code, body=None, ctype="application/json", extra=None):
            data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(data)))
            if b.security_headers:
                for h, v in (("strict-transport-security", "max-age=31536000"), ("x-frame-options", "DENY"),
                             ("x-content-type-options", "nosniff"), ("content-security-policy", "default-src 'none'"),
                             ("referrer-policy", "no-referrer")):
                    self.send_header(h, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if data:
                self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("content-length") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n))
            except ValueError:
                return {}

        def _user(self):
            h = self.headers.get("authorization", "")
            if not h.lower().startswith("bearer "):
                return None
            tok = h[7:].strip()
            parts = tok.split(".")
            if len(parts) != 3:
                return None
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            except Exception:  # noqa: BLE001
                return None
            if header.get("alg") == "none":
                return payload.get("sub") if b.accept_alg_none else None
            secret = "secret" if b.weak_secret else SECRET
            expected = _b64(hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
            return payload.get("sub") if hmac.compare_digest(expected, parts[2]) else None

        def do_POST(self):
            b.calls.append(("POST", self.path))
            body = self._body()
            if self.path == "/login":
                if b.login_rate_limit and b.failed_logins >= 5:
                    return self._send(429, {"erro": "muitas tentativas"}, extra={"retry-after": "60"})
                u, pw = body.get("username"), body.get("password")
                if (u in USERS and pw == PASSWORD) or (u in b.reg_users and b.reg_users[u]["password"] == pw):
                    return self._send(200, {"token": make_jwt(u, "secret" if b.weak_secret else SECRET, with_exp=not b.jwt_no_exp)})
                b.failed_logins += 1
                return self._send(401, {"erro": "credenciais"})
            if self.path == "/register":
                u = body.get("username")
                if not u or not body.get("password"):
                    return self._send(400, {"erro": "dados"})
                b.reg_users[u] = {"password": body["password"], "admin": bool(b.mass_assign_vulnerable and body.get("admin") is True)}
                return self._send(200, {"status": "success"})
            if self.path == "/webhook":
                if b.webhook_unsigned or self.headers.get("x-twilio-signature"):
                    return self._send(200, {"ok": True})
                return self._send(403, {"erro": "assinatura"})
            return self._send(404, {"erro": "nf"})

        def do_PUT(self):
            b.calls.append(("PUT", self.path))
            self._body()  # consome o corpo para não corromper a conexão keep-alive
            u = urlparse(self.path).path.split("/")
            me = self._user()
            if b.always_401_on_put or not me:
                return self._send(401, {"erro": "token"})
            if len(u) >= 4 and u[1] == "users" and u[3] == "email":
                target = u[2]
                if b.bola_ignores_id:
                    return self._send(204)
                if target not in USERS:
                    return self._send(404, {"erro": "usuario"})
                if b.bola_vulnerable or target == me:
                    return self._send(204)
                return self._send(403, {"erro": "proibido"})
            return self._send(404, {"erro": "nf"})

        def do_DELETE(self):
            b.calls.append(("DELETE", self.path))
            self._body()
            me = self._user()
            if not me or b.always_401_on_put:
                return self._send(401, {"erro": "token"})
            if self.path.startswith("/users/"):
                if b.bfla_vulnerable or USERS.get(me) == "admin":
                    return self._send(204)
                return self._send(403, {"erro": "proibido"})
            return self._send(404, {"erro": "nf"})

        def do_GET(self):
            u = urlparse(self.path)
            b.calls.append(("GET", self.path))
            if u.path == "/":
                if b.rate_limit and sum(1 for c in b.calls if c == ("GET", "/")) > 5:
                    return self._send(429, {"erro": "limite"}, extra={"retry-after": "5"})
                return self._send(200, {"ok": True})
            if u.path == "/openapi.json":
                return self._send(200, spec_for(b))
            if u.path == "/createdb":
                b.hits += 1  # efeito colateral: o scanner NÃO pode chamar isto
                return self._send(200, {"msg": "banco recriado"})
            if u.path == "/me":
                me = self._user()
                if not me and not b.protected_is_public:
                    return self._send(401, {"erro": "token"})
                is_admin = USERS.get(me) == "admin" or bool(b.reg_users.get(me, {}).get("admin"))
                data = {"username": me or "anonimo", "admin": is_admin}
                if b.leak_me:
                    data["password_hash"] = "$2b$12$abcdefghijklmnopqrstuv"
                return self._send(200, {"data": data})
            if u.path == "/cron":
                if b.cron_open or self.headers.get("authorization", "").startswith("Bearer segredo-cron"):
                    return self._send(200, {"executado": True})
                return self._send(401, {"erro": "segredo"})
            if u.path == "/auth/providers":
                return self._send(200, {"providers": ["google"]}) if b.has_providers else self._send(404, {"erro": "nf"})
            if u.path == "/service" and "wsdl" in u.query.lower() and b.wsdl:
                policy = '<wsp:Policy><sp:UsernameToken/></wsp:Policy>' if b.wsdl == "secured" else ""
                xml = ('<?xml version="1.0"?><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">'
                       '<wsdl:portType><wsdl:operation name="Saldo"/><wsdl:operation name="Extrato"/></wsdl:portType>' + policy + '</wsdl:definitions>')
                return self._send(200, xml.encode(), "text/xml")
            if u.path == "/api/contas":
                if b.spec_marks_secured_but_open or self._user():
                    return self._send(200, {"contas": [1, 2]})
                return self._send(401, {"erro": "token"})
            if u.path.startswith("/api/contas/") and b.bola_path:
                me = self._user()
                if not me:
                    return self._send(401, {"erro": "token"})
                owner = {"c-ana": "ana", "c-bruno": "bruno"}.get(u.path.rsplit("/", 1)[1])
                if owner is None:
                    return self._send(404, {"erro": "nf"})
                if owner == me or b.bola_path == "vulnerable":
                    return self._send(200, {"conta": u.path.rsplit("/", 1)[1], "dono": owner})
                return self._send(403, {"erro": "proibido"})
            if u.path == "/admin/usuarios":
                me = self._user()
                if not me:
                    return self._send(401, {"erro": "token"})
                if USERS.get(me) == "admin" or b.bfla_vulnerable:
                    return self._send(200, {"usuarios": list(USERS)})
                return self._send(401 if b.bfla_returns_401 else 403, {"erro": "proibido"})
            if u.path == "/publico/clientes":
                if b.leak_public:
                    return self._send(200, {"clientes": [{"nome": "Ana", "cpf": "123.456.789-00", "password": "abc12345"}]})
                return self._send(200, {"clientes": [{"nome": "Ana"}]})
            if u.path == "/.env":
                if b.leak_env:
                    return self._send(200, b"DB_PASSWORD=super-secreta\nAPI_KEY=abc\n", "text/plain")
                return self._send(404, {"erro": "nf"})
            if u.path == "/api/preview":
                target = parse_qs(u.query).get("url", [""])[0]
                if b.ssrf_vulnerable and target:
                    try:
                        urllib.request.urlopen(target, timeout=3).read()
                    except Exception:  # noqa: BLE001
                        pass
                return self._send(200, {"ok": True})
            return self._send(404, {"erro": "nf"})

    return H


class LabServer:
    def __init__(self, behavior: Behavior | None = None):
        self.behavior = behavior or Behavior()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.behavior))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
