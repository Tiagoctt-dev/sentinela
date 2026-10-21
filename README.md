# ⬢ Sentinela — Scanner de Segurança de APIs

Prova de conceito de um scanner que aponta para uma API, roda uma bateria de
verificações de segurança e mostra **onde estão as vulnerabilidades**, com um
**score de conformidade** por categoria e histórico de execuções num dashboard.

Nasceu como ferramenta pessoal para auditar meu próprio sistema financeiro
(**Seu CFO Pessoal**), que expõe várias APIs — autenticação, export de dados,
webhook de WhatsApp e cron. É a versão enxuta da ideia de uma plataforma de
segurança de APIs de grau bancário.

## Stack

- **Backend**: Python (FastAPI) — domínio do scanner, orquestração e API REST.
- **Frontend**: React (Vite) — dashboard com histórico de scans e relatório interativo.
- **Persistência**: PostgreSQL — histórico de scans e evolução do score.
- **IA Generativa**: Gemini — único provedor de IA suportado neste projeto.
- **Empacotamento**: Docker / docker compose.

## O que ele verifica

| Categoria | Exemplos de checagem |
|---|---|
| **Autorização & Acesso** | rotas exigem sessão? consultas escopadas por `userId` (anti-BOLA)? endpoint protegido nega acesso sem login? |
| **Token & Sessão** | cookies `httpOnly`/`secure`/`sameSite`? tokens temporários expiram? DPoP? |
| **OAuth · OIDC · PKCE** | OAuth 2.0 / OpenID Connect configurado? PKCE + `state` no fluxo? |
| **Integridade** | webhooks validam assinatura? endpoints internos exigem `Bearer`? |
| **Cabeçalhos** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Validação** | schema validation (Zod), hash de senha (bcrypt) |
| **Transporte** | HTTPS, mTLS |
| **Inventário de Endpoints** | discovery automático de rotas (código + spec OpenAPI/Swagger) e comparação com o inventário declarado — sinaliza shadow/zombie APIs (OWASP API9:2023) |

Cada checagem vira um **achado** com severidade (Crítico → Info). O score de
cada categoria começa em 100 e perde pontos por falha (penalidade cheia) ou
aviso (metade).

## Como funciona

Três frentes, combinadas num score único e persistidas como um `ScanRun` no Postgres:

- **Estática** — lê os arquivos do projeto-alvo e deduz as práticas implementadas
  (sem executar nada).
- **Dinâmica** — dispara requisições reais contra o app rodando e observa o
  comportamento (status, headers, cookies). Se o app estiver fora do ar, essa
  parte é pulada com elegância.
- **Discovery de endpoints** — roda junto da estática (varre o código por rotas
  Next.js/Express) e da dinâmica (sonda locais conhecidos de spec OpenAPI/Swagger
  no app rodando). Endpoints encontrados que não constam no `target` configurado
  são sinalizados como possíveis shadow/zombie APIs.
- **IA Generativa (Gemini)** — envia os achados para o Gemini, que gera um
  resumo executivo e recomendações técnicas priorizadas. Sem chave configurada,
  o scanner usa as recomendações estáticas.

## Configuração da IA (opcional, mas recomendado)

```bash
# 1. copie o exemplo
cp .env.example .env
# 2. edite .env e cole sua GEMINI_API_KEY
```

O `.env` está no `.gitignore` — a chave nunca vai pro repositório.

## Uso local (recomendado pro dia a dia)

Só o Postgres roda em Docker; backend e frontend rodam direto na sua máquina —
`uvicorn --reload` e `npm run dev` de verdade, sem container no meio. Salvar um arquivo já
reflete na hora, sem restart de nada.

```bash
# 1. sobe só o banco (fica rodando em background)
docker compose up -d postgres
```

Backend (num terminal):

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate   # ou source .venv/bin/activate no Linux/Mac
pip install -r requirements.txt
cp ../.env.example .env
# edite backend/.env: GEMINI_API_KEY e
# DATABASE_URL=postgresql+psycopg://sentinela:sentinela@localhost:5439/sentinela
uvicorn app.main:app --reload
```

Frontend (noutro terminal):

```bash
cd frontend
npm install
npm run dev
```

- Backend (API): <http://localhost:8000>
- Frontend (dashboard): <http://localhost:5173>

Dispare um scan pelo dashboard (aba Projetos → "Rodar scan") ou via API:

```bash
curl -X POST http://localhost:8000/api/scans -H "content-type: application/json" \
  -d '{"target": "cfo-pessoal"}'
```

Pra derrubar o banco: `docker compose down` (ou `down -v` se mudar o schema).

CLI fina, sem subir a API (roda o pipeline direto e imprime o JSON do resultado):

```bash
cd backend
python -m app.cli cfo-pessoal --no-dynamic   # só estática (não precisa do app no ar)
python -m app.cli cfo-pessoal --no-ai        # sem a camada de IA
python -m app.cli cfo-pessoal --url http://localhost:3000
```

## Alvos

Cada alvo é um JSON em [`backend/targets/`](./backend/targets) descrevendo onde
está o código e quais endpoints sondar. Para auditar outro projeto, é só criar
um novo arquivo lá — o backend o descobre automaticamente e persiste no Postgres
na primeira vez que um scan roda contra ele.

## Estrutura

```
backend/
  app/
    domain/
      models.py              # severidades, categorias, achados
      scoring.py              # score por categoria + geral
      static_analyzer.py      # checagens que leem o código
      dynamic_analyzer.py     # probes contra o app rodando
      active_probes.py        # probes ativos (BOLA/auth/mass assignment)
      endpoint_discovery.py   # discovery de endpoints (código + spec OpenAPI/Swagger)
      ai_recommendations.py   # camada de IA (Gemini) — recomendações + resumo
      owasp_api_top10.py      # taxonomia OWASP API Top 10 (2023) — base de conhecimento
      pipeline.py              # orquestra estático + dinâmico + probes + IA
    db/
      models.py                # Target, ScanRun, Finding (SQLAlchemy)
      session.py
    api/
      routes_targets.py
      routes_scans.py
    main.py                    # app FastAPI
    cli.py                      # CLI fina para rodar scans sem a API
  targets/
    cfo-pessoal.json           # alvo de exemplo
    vampi.json                 # alvo de teste (API deliberadamente vulnerável)
frontend/
  src/
    pages/ScanList.tsx         # histórico de scans
    pages/ScanDetail.tsx       # gauge + barras por categoria + achados
    components/
    api/client.ts
docker-compose.yml
docs/
  owasp-api-top10.md           # OWASP API Top 10 (2023) + mapa de cobertura
```

## Base de conhecimento: OWASP API Top 10 (2023)

O scanner é ancorado no **OWASP API Security Top 10 (2023)**: cada achado é
marcado com a categoria (`API1:2023` … `API10:2023`) e a taxonomia é injetada
como contexto na camada de IA, para recomendações embasadas na fonte. Ver
[docs/owasp-api-top10.md](./docs/owasp-api-top10.md).

## Roadmap

- [x] Camada de IA para recomendações priorizadas (Gemini)
- [x] Histórico de scans e evolução do score (PostgreSQL)
- [x] Dashboard React + empacotamento Docker
- [x] Discovery de endpoints por código e por spec OpenAPI/Swagger
- [ ] Discovery por OIDC (`/.well-known/openid-configuration`)
- [ ] Integração com OWASP ZAP para scan dinâmico profundo
- [ ] Checagens FAPI avançadas (PAR, request objects assinados)
- [ ] Cadastro de alvos pela própria UI (hoje é via JSON em `backend/targets/`)

---

PoC · scanner de segurança de APIs · estático + dinâmico · Python + React + PostgreSQL.
