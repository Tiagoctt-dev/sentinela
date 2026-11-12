# Estratégia de testes

O princípio: **cada verificação de segurança é testada contra um alvo real de laboratório** (uma API HTTP local, só em `127.0.0.1`,
com comportamento configurável), em versão **vulnerável**, **segura** e com **falsos positivos conhecidos**. Mocks ficam só nos testes
(por exemplo, um `run_scan` lento para provar o timeout); nada simulado entra no produto.

## Backend (`backend/tests`, pytest)

| Arquivo | O que prova |
|---|---|
| `lab_server.py` | o alvo de laboratório (JWT, BOLA, BFLA, SSRF, mass assignment, SOAP, vazamentos, limites…) |
| `test_classification_and_scoring.py` | regras puras: estados, confiança, score, teto só para falha confirmada, política, proteção de rede, base editorial completa |
| `test_policies_vs_lab.py` | políticas contra o laboratório: detecção, aprovação do alvo seguro, **falsos positivos** (rota pública + JWT forjado, API que ignora o id, 401 ≠ aprovado, rajada em rota que sempre nega), SSRF e alcance do canário, **portão de escrita**, regressão `/createdb`, alvo fora do ar, login inválido |
| `test_policies_more_dynamic.py` | demais políticas dinâmicas: JWT exp/segredo, exposição, mass assignment, cabeçalhos, TLS, webhook, cron, OIDC, brute force, descoberta, SOAP |
| `test_static_rules.py` | as regras de código (genéricas e Next.js) com projetos criados em disco; redação de segredos; detecção de stack |
| `test_api_modes_and_persistence.py` | papéis (viewer/analyst/admin), login e bloqueio, **persistência API = banco**, isolamento entre execuções, **diferença externo × autenticado**, comparação (não executado ≠ corrigido), segredos criptografados, migração de segredo antigo, destinos perigosos, timeout 504 |
| `test_routes_and_dashboard.py` | rotas/verificações e dashboard: contadores consistentes com as listas, estados vazios |

Cada política do catálogo tem **ao menos um teste dedicado** — `scripts/gen_policy_docs.py` liga política → testes em `docs/politicas.md`
e informa se alguma ficar sem teste.

## Frontend (`frontend/src`, Vitest)

- `lib/results.test.ts`: vocabulário de estados (estado desconhecido **nunca** vira "aprovado"), ordenação, utilitários.
- `test/contract.test.tsx`: usa **fixtures geradas pelo próprio backend** (`backend/scripts/dump_contract_fixture.py`) e prova que a UI
  mostra exatamente o que a API devolve: nenhum campo perdido, classificação intacta, totais dos gráficos = totais das listas,
  filtros só reduzem a lista, escopo/limitações presentes.

## Comandos

```bash
cd backend
.venv/Scripts/python -m pytest                  # tudo (~2 min)
.venv/Scripts/python -m pytest tests/test_policies_vs_lab.py -k BOLA
.venv/Scripts/python scripts/gen_policy_docs.py          # regenera docs/politicas.md
.venv/Scripts/python scripts/dump_contract_fixture.py    # regenera as fixtures do front

cd frontend
npm run typecheck && npm run lint && npm test && npm run build
```

## Não coberto por testes automatizados

- Fluxos de navegação ponta a ponta no navegador (verificados manualmente em desktop, tablet e celular; sem Playwright/Cypress).
- Integrações reais com GitHub e Slack (só validação de destino, criptografia e mascaramento; as chamadas externas dependem de credenciais).
- Chamadas reais às APIs de IA (Gemini/Groq); os testes rodam sem chaves.
- Análise de código em linguagens além de Python/JS (as regras genéricas têm padrões para Java, Go, C#, PHP e Ruby, mas só Python/JS foram exercitados).
