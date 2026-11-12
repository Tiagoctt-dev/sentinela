# ⬢ Sentinela — Scanner de Segurança de APIs

Aponta para uma API, executa uma bateria de verificações alinhadas ao **OWASP API Security Top 10 (2023)** e mostra
**quais vulnerabilidades foram confirmadas, quais são apenas indícios e o que deixou de ser testado** — com a requisição que
provou cada falha, a recomendação de correção e a cobertura de cada execução.

> O Sentinela mede **conformidade nas verificações executadas**. Ele não garante que um sistema esteja seguro: toda tela
> mostra a cobertura ao lado do resultado, e "aprovado" significa "nenhuma falha encontrada no que foi testado".

## Stack

- **Backend:** Python 3.10+ · FastAPI · SQLAlchemy · PostgreSQL (SQLite nos testes)
- **Frontend:** React 18 · TypeScript · Vite (sem biblioteca de componentes; gráficos em SVG)
- **IA (opcional):** Gemini e Groq, em paralelo, só para redigir recomendações — nunca decidem o resultado de um teste

## Início rápido

```bash
# 1) banco (só o Postgres roda em Docker)
docker compose up -d postgres

# 2) backend
cd backend
python -m venv .venv && . .venv/Scripts/activate      # Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env                                # ajuste DATABASE_URL e, se quiser, as chaves de IA
uvicorn app.main:app --reload                          # http://localhost:8000

# 3) frontend
cd ../frontend
npm install
npm run dev                                            # http://localhost:5173
```

No primeiro acesso a tela pede para **criar o administrador**. Depois, em **Projetos**, cadastre um sistema (ou use um exemplo)
e clique em **Rodar scan**. Para uso local sem login: `SENTINELA_AUTH=off` em `backend/.env`.

### Variáveis de ambiente (todas opcionais)

Ver [`.env.example`](.env.example). As principais: `DATABASE_URL`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `SENTINELA_SECRET_KEY`
(criptografa credenciais de teste e assina sessões; se vazia é gerada em `backend/.secret_key`), `SENTINELA_AUTH`,
`SENTINELA_BLOCK_PRIVATE_TARGETS`, `SENTINELA_TARGET_ALLOWLIST`, `PUBLIC_API_URL` e `PUBLIC_APP_URL`.

## Como uma análise funciona

```
Projeto + (credenciais de teste) ──► pipeline ──► classificação ──► escopo/cobertura ──► banco ──► tela / integrações
```

Há dois modos, e a diferença entre eles é **real e declarada em cada scan**:

| | Scan externo (só a URL) | Scan autenticado (com usuários de teste) |
|---|---|---|
| O que roda | cabeçalhos, CORS, TLS, rate limit, rotas de debug, spec OpenAPI (rotas públicas), SSRF, SOAP | **tudo do externo +** JWT, rota protegida, exposição autenticada, BOLA, BFLA, mass assignment |
| O que NÃO roda | verificações que exigem login — aparecem como **não executadas**, com o motivo | só o que depender de configuração ausente (também listado) |
| Cobertura | menor, e informada | maior, e informada |

As verificações executadas nos dois modos produzem o mesmo resultado (há teste automático para isso). Detalhes em
[docs/arquitetura.md](docs/arquitetura.md).

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/arquitetura.md](docs/arquitetura.md) | arquitetura, diretórios, fluxo de uma varredura, modelo de dados, modos de análise |
| [docs/classificacao.md](docs/classificacao.md) | estado × confiança × severidade, cálculo do score, escopo e cobertura |
| [docs/politicas.md](docs/politicas.md) | catálogo das 50 políticas: critérios, evidências, limitações, referências e testes (gerado) |
| [docs/api.md](docs/api.md) | contratos dos endpoints internos |
| [docs/testes.md](docs/testes.md) | estratégia de testes e comandos |
| [docs/limitacoes.md](docs/limitacoes.md) | o que a ferramenta **não** cobre e débitos conhecidos |
| [docs/design-system.md](docs/design-system.md) | tokens, componentes, contraste testado e regras de texto da interface (catálogo vivo em `/design`) |
| [docs/diagnostico-tecnico.md](docs/diagnostico-tecnico.md) | diagnóstico feito antes da refatoração |

## Validação

```bash
cd backend && .venv/Scripts/python -m pytest          # 166 testes (regras, políticas vs. alvo de laboratório, API, persistência, endurecimento)
cd backend && .venv/Scripts/python -m ruff check .     # lint
cd frontend && npm run typecheck && npm run lint && npm test && npm run build   # 94 testes (contrato, contraste AA, erros da API)
```

## Segurança do próprio Sentinela

Credenciais de teste, tokens do GitHub e URLs do Slack são **criptografados** no banco; destinos de rede (alvos e integrações)
passam por proteção contra SSRF; testes que **alteram dados do alvo** só rodam com autorização explícita no projeto;
toda ação de escrita é auditada (sem corpo nem senhas). Limites conhecidos em [docs/limitacoes.md](docs/limitacoes.md).

Sessões são revogáveis (sair e trocar a senha invalidam o token), o bloqueio de tentativas de login fica no banco,
a execução de scans é travada por projeto, existe perfil de scan **seguro** (nunca envia escrita), aceite de risco com
**validade** e histórico por achado, exportação **SARIF 2.1.0**, importação de spec OpenAPI (JSON/YAML), métricas
Prometheus em `/api/metrics` e política de retenção (`SENTINELA_*_RETENTION_DAYS`). CI em `.github/workflows/ci.yml`;
a imagem do backend roda sem root, com healthcheck e a chave de criptografia em volume (`/data`).

**Use apenas em sistemas que você tem autorização para testar** — preferencialmente ambientes de homologação.
