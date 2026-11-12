"""Regras de análise de código: cada política contra um projeto vulnerável e um seguro, criados em disco."""

import asyncio
import json
import textwrap
from pathlib import Path

import pytest

from app.domain.classify import classify_all
from app.domain.endpoint_discovery import build_static_finding
from app.domain.generic_static import detect_stack, run_generic_static
from app.domain.models import STATE
from app.domain.pipeline import run_scan
from app.domain.static_analyzer import index_project, run_static


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def states(findings):
    classify_all(findings)
    return {f.id: f for f in findings}


# ====================================================================================== regras genéricas (S-SEC-*)
@pytest.fixture()
def insecure_py(tmp_path):
    write(tmp_path, "app/main.py", '''
        import hashlib, requests, jwt
        from flask import Flask
        app = Flask(__name__)
        API_KEY = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
        password = "SuperSecretaSenha2026"
        def login(user, pwd):
            h = hashlib.md5(pwd.encode()).hexdigest()
            row = db.execute(f"SELECT * FROM users WHERE name = '{user}'")
            r = requests.get("https://interno", verify=False)
            claims = jwt.decode(token, options={"verify_signature": False})
        CORS(app)
        allow_origins = ["*"]
        app.run(debug=True)
    ''')
    return tmp_path


@pytest.fixture()
def secure_py(tmp_path):
    write(tmp_path, "app/main.py", '''
        import os, bcrypt, jwt
        SECRET = os.environ["JWT_SECRET"]
        def login(user, pwd):
            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
            row = db.execute("SELECT * FROM users WHERE name = %s", (user,))
            claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    ''')
    return tmp_path


@pytest.mark.parametrize("check", ["S-SEC-01", "S-SEC-02", "S-SEC-03", "S-SEC-04", "S-SEC-05", "S-SEC-06", "S-SEC-07"])
def test_regras_genericas_detectam_o_projeto_inseguro(insecure_py, check):
    f = states(run_generic_static({"projectPath": str(insecure_py)}))[check]
    assert f.state in (STATE.VULNERABLE, STATE.LIKELY), f"{check}: {f.state} {f.detail}"
    assert f.evidence and "app/main.py:" in f.evidence  # arquivo e linha da ocorrência


@pytest.mark.parametrize("check", ["S-SEC-01", "S-SEC-02", "S-SEC-03", "S-SEC-04", "S-SEC-05", "S-SEC-06", "S-SEC-07"])
def test_regras_genericas_aprovam_o_projeto_seguro(secure_py, check):
    assert states(run_generic_static({"projectPath": str(secure_py)}))[check].state == STATE.PASSED


def test_S_SEC_01_nunca_copia_o_segredo_para_a_evidencia(insecure_py):
    f = states(run_generic_static({"projectPath": str(insecure_py)}))["S-SEC-01"]
    assert "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q" not in f.evidence
    assert "SuperSecretaSenha2026" not in f.evidence
    assert "[REDACTED]" in f.evidence


def test_S_SEC_01_ignora_arquivos_de_teste_e_exemplos(tmp_path):
    write(tmp_path, "tests/test_x.py", 'password = "SenhaDeTesteBemLonga123"\n')
    write(tmp_path, "src/ok.py", "x = 1\n")
    assert states(run_generic_static({"projectPath": str(tmp_path)}))["S-SEC-01"].state == STATE.PASSED


def test_S_SEC_05_nao_acusa_consulta_parametrizada(tmp_path):
    write(tmp_path, "db.py", 'cur.execute("SELECT * FROM t WHERE id = %s", (i,))\nsession.query(User).filter(User.id == i)\n')
    assert states(run_generic_static({"projectPath": str(tmp_path)}))["S-SEC-05"].state == STATE.PASSED


def test_sem_pasta_de_codigo_nada_e_aprovado(tmp_path):
    assert run_generic_static({"projectPath": str(tmp_path / "nao-existe")}) == []
    f = states(run_static({"projectPath": str(tmp_path / "nao-existe")}))["S-ENV-00"]
    assert f.state == STATE.NOT_RUN


# ====================================================================================== detecção de stack
def test_regras_de_nextjs_so_rodam_em_projeto_nextjs(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "4"}}))
    write(tmp_path, "server.js", "app.get('/x', (req,res)=>res.send('ok'))\n")
    assert detect_stack(str(tmp_path)) == "generic"
    r = asyncio.run(run_scan({"name": "g", "projectPath": str(tmp_path)}, dynamic=False, ai=False))
    ids = {f["id"] for f in r["findings"]}
    assert "S-AUTHZ-01" not in ids and "S-OIDC-01" not in ids  # regras Next.js fora de contexto
    assert "S-SEC-01" in ids  # regras genéricas rodam sempre
    write(tmp_path, "package.json", json.dumps({"dependencies": {"next": "15"}}))
    assert detect_stack(str(tmp_path)) == "nextjs"


# ====================================================================================== regras específicas de Next.js
@pytest.fixture()
def secure_next(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"next": "15", "next-auth": "5.0.0", "bcrypt": "5"}}))
    write(tmp_path, "middleware.ts", "export const config = { matcher: ['/((?!login).*)'] }\n")
    write(tmp_path, "next.config.js", "module.exports = { async headers() { return [] } }\n")
    write(tmp_path, "prisma/schema.prisma", "model Item {\n  id String @id\n  userId String\n}\n")
    write(tmp_path, "src/app/api/items/route.ts", '''
        import { auth } from "@/auth"
        import { z } from "zod"
        export async function PUT(req) {
          const session = await auth()
          if (!session) return new Response("no", { status: 401 })
          const body = z.object({ name: z.string() }).parse(await req.json())
          return prisma.item.update({ where: { id: body.id, userId: session.user.id }, data: body })
        }
    ''')
    write(tmp_path, "src/app/api/webhook/route.ts", 'const ok = validateRequest(req.headers.get("x-twilio-signature"))\n')
    write(tmp_path, "src/app/api/cron/route.ts", 'if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) return 401\n')
    write(tmp_path, "src/lib/session.ts", "cookies: { httpOnly: true, secure: true, sameSite: 'lax' }\nconst token = { verificationToken: 1, expires: 2 }\nconst dpop = 'DPoP'\nconst mtls = 'mutual tls'\n")
    return tmp_path


@pytest.fixture()
def insecure_next(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"next": "15"}}))
    write(tmp_path, "prisma/schema.prisma", "model Item {\n  id String @id\n  userId String\n}\n")
    write(tmp_path, "src/app/api/items/route.ts", '''
        export async function PUT(req) {
          const body = await req.json()
          return prisma.item.update({ where: { id: body.id }, data: body })
        }
    ''')
    return tmp_path


NEXT_RULES = ["S-AUTHZ-01", "S-AUTHZ-02", "S-BOLA-01", "S-TOKEN-01", "S-TOKEN-02", "S-TOKEN-03", "S-OIDC-01", "S-OIDC-02",
              "S-INTEG-01", "S-INTEG-02", "S-HEAD-01", "S-INPUT-01", "S-INPUT-02", "S-TLS-01"]


@pytest.mark.parametrize("check", NEXT_RULES)
def test_regras_nextjs_aprovam_projeto_bem_configurado(secure_next, check):
    f = states(run_static({"projectPath": str(secure_next)}))[check]
    assert f.state == STATE.PASSED, f"{check}: {f.state} — {f.detail}"


@pytest.mark.parametrize("check", [c for c in NEXT_RULES if c != "S-OIDC-02"])  # next-auth ausente => sem PKCE confirmado
def test_regras_nextjs_apontam_projeto_sem_protecoes(insecure_next, check):
    f = states(run_static({"projectPath": str(insecure_next)}))[check]
    assert f.state in (STATE.VULNERABLE, STATE.LIKELY), f"{check}: {f.state} — {f.detail}"


def test_S_BOLA_01_aponta_operacao_por_id_sem_filtro_de_dono(insecure_next):
    f = states(run_static({"projectPath": str(insecure_next)}))["S-BOLA-01"]
    assert f.state == STATE.LIKELY and f.confidence == "indicative"  # estático: indício, não prova
    assert "route.ts" in f.detail


def test_regras_estaticas_por_indicio_nunca_reprovam_a_politica_sozinhas(insecure_next):
    from app.domain.policy import evaluate_policy

    r = states(run_static({"projectPath": str(insecure_next)}))
    estaticos_indicativos = [f for f in r.values() if f.id in ("S-AUTHZ-02", "S-AUTHZ-01", "S-BOLA-01")]
    assert evaluate_policy(estaticos_indicativos)["passed"] is True


# ====================================================================================== descoberta no código
def test_S_DISC_01_lista_rotas_do_codigo_e_aponta_as_fora_do_inventario(secure_next):
    idx = index_project(str(secure_next))
    sem_inventario = states([build_static_finding({"name": "x"}, idx)])["S-DISC-01"]
    assert sem_inventario.state == STATE.LIKELY  # rotas do código que o projeto não declarou
    paths = {e["path"] for e in sem_inventario.data["endpoints"]}
    assert {"/api/items", "/api/webhook", "/api/cron"} <= paths
    inventariado = {"name": "x", "endpoints": {"protectedGet": sorted(paths)}}
    assert states([build_static_finding(inventariado, idx)])["S-DISC-01"].state == STATE.PASSED


def test_S_DISC_01_sem_rotas_nao_e_aplicavel(tmp_path):
    write(tmp_path, "readme.md", "x")
    write(tmp_path, "a.ts", "const a = 1\n")
    f = states([build_static_finding({"name": "x"}, index_project(str(tmp_path)))])["S-DISC-01"]
    assert f.state == STATE.NOT_APPLICABLE
