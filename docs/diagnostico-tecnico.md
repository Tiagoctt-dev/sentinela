# Diagnóstico técnico do Sentinela (22/10/2026)

Estado verificado no código antes da refatoração. Backup do projeto em `Documents/sentinela-backup-2026-10-22`.

## Arquitetura (como é hoje)
- **Backend** FastAPI + SQLAlchemy (Postgres). `domain/pipeline.py` orquestra: análise estática → dinâmica (`dynamic_analyzer`) → probes ativos com login (`active_probes`) → checagens por spec OpenAPI (`spec_checks`) → SOAP → IA → política → persistência (`api/routes_scans.py`).
- **Frontend** React + TypeScript + Vite, CSS único (`styles.css`), sem biblioteca de componentes.
- **Fluxo de uma varredura:** `POST /api/scans` → `run_target_scan` → `run_scan` → grava `ScanRun` + `FindingModel` → dispara webhook/Slack/GitHub.

## Problemas encontrados (priorizados)

### Segurança do próprio Sentinela
| # | Problema | Gravidade |
|---|---|---|
| S1 | Token do GitHub gravado em texto puro (`github_integrations.token`). O formulário afirmava que ficava criptografado — **afirmação falsa**. | Alta |
| S2 | URL do alvo e destinos de integração sem validação de rede: um usuário com permissão de escrita pode apontar o scanner para metadados de nuvem (169.254.169.254) ou serviços internos (SSRF por design). | Alta |
| S3 | Testes de BOLA/BFLA executam `PUT`/`DELETE` reais no alvo sem confirmação de que o ambiente permite escrita. Se a API for vulnerável, o teste altera/apaga dados. | Alta |
| S4 | URL do webhook do Slack devolvida integralmente pela API (é um segredo). | Média |
| S5 | Scan roda dentro da requisição HTTP sem timeout global nem limite de concorrência. | Média |
| S6 | Canário de SSRF guarda tokens em memória sem limite. | Baixa |
| S7 | Não há isolamento por organização: todo usuário logado lê todos os projetos/scans. Limitação de modelo, não bug. | Registrada |
| S8 | Token de sessão fica em `localStorage` e não é revogável antes de expirar (8 h). | Registrada |

### Qualidade das verificações
| # | Problema | Efeito |
|---|---|---|
| Q1 | O resultado é só `PASS/FAIL/WARN/SKIP`. `SKIP` mistura "não executado", "não aplicável" e "falha de execução". `WARN` mistura "indício" e "inconclusivo". | Ausência de evidência é lida como aprovação; indício é lido como falha. |
| Q2 | Não existe "confiança da detecção". Severidade fixa por regra, sem separar o quanto foi provado. | Um indício crítico derruba o score igual a uma prova. |
| Q3 | O teto de score (crítico → 50, alto → 70) usa qualquer `FAIL`, mesmo sem prova. Por isso o scan externo e o autenticado do VAmPI deram 50 e parecem iguais. | O número esconde a diferença de profundidade. |
| Q4 | Nenhuma medida de **cobertura**: o score não diz quantas verificações deixaram de rodar. | Um sistema pode "pontuar bem" com 60% dos testes não executados. |
| Q5 | Achados sem resumo, impacto, cenário, pré-requisitos, limitações, CWE ou ativo afetado estruturado. Texto vive dentro de cada probe. | Linguagem inconsistente. |
| Q6 | Verificações agregadas (D-SPEC-01/02, BFLA automático) não guardam por rota o método, o caminho e o HTTP. | A tela de rotas não tem de onde ler. |
| Q7 | Zero testes automatizados no repositório. | Nenhuma regressão é detectada. |

### Autenticado × demonstração (investigado)
- Os dois modos usam **o mesmo pipeline**. Não há cache (`grep`), nem dados simulados, nem resultados escondidos pelo front.
- A diferença real é funcional: com credenciais cadastradas, `run_active_probes` roda (JWT, BOLA, BFLA, exposição, rota protegida). Sem elas, essas verificações **não rodam** e o scan **não informa isso**. O score igual (50/100) vem de Q3.
- Correção planejada: registrar o **escopo** de cada scan (verificações executadas × não executadas, com o motivo) e exibir cobertura ao lado do score.

### Frontend
- Telas "Scans" e "Achados" misturam resultados e verificações; não há visão de rotas.
- Sem dashboard com dados reais além de 4 contadores.
- Navegação sem breadcrumbs; "voltar" depende do histórico.
- Estados desconhecidos (`SKIP`) são desenhados como neutros/aprovados em algumas listas.

### Manutenção
- `Targets.tsx` (560 linhas) e `Integrations.tsx` (434) acumulam lógica de formulário, API e apresentação.
- `routes_integrations.py` repete CRUD três vezes.
- Sem lint configurado; apenas `tsc`.

## Plano
1. **Segurança:** criptografar token GitHub e mascarar Slack; validar destinos de rede; exigir autorização explícita para testes que alteram dados; timeout/limite de concorrência.
2. **Modelo de resultados:** `state` × `confidence` × `severity`; base editorial por verificação; escopo e cobertura por scan; `observações` por rota.
3. **Testes:** pytest com alvo local seguro e vulnerável; regressão de falsos positivos.
4. **Frontend:** navegação, Achados de segurança, Rotas e verificações, dashboard com gráficos reais, páginas de detalhe.
5. **Documentação e validação final.**
