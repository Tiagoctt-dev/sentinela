# Classificação dos resultados

Cada verificação produz **três informações independentes**. Misturá-las leva a conclusões erradas (ex.: tratar um indício
crítico como prova, ou "não executado" como "aprovado").

| Eixo | Pergunta que responde | Valores |
|---|---|---|
| **Severidade** | Se a falha for real, qual o impacto? | Crítica · Alta · Média · Baixa · Informativa (fixa por política, com justificativa) |
| **Confiança** | O quanto esta verificação *prova*? | Confirmada · Indício · — |
| **Estado** | O que aconteceu neste scan? | ver abaixo |

## Estados

| Estado | Significado | Conta no score? | Conta na cobertura? |
|---|---|---|---|
| `vulnerable` — Vulnerabilidade confirmada | a condição da falha foi observada e comprovada | sim | sim |
| `likely` — Vulnerabilidade provável | indício parcial; exige validação manual | sim, metade | sim |
| `inconclusive` — Inconclusivo | executou, mas a evidência não permite concluir (ex.: 401 em vez de 403, controle falhou) | não | sim |
| `error` — Erro de execução | falha de rede, timeout ou resposta inválida | não | **não** (conta como não executado) |
| `passed` — Aprovado no escopo verificado | nenhuma falha **dentro do que foi testado** | não | sim |
| `not_run` — Não executado | aplicável, mas faltou pré-requisito (credencial, configuração, autorização) | não | **não** |
| `not_applicable` — Não aplicável | o alvo não tem a superfície testada | não | fora do cálculo |

Regras que impedem falsos positivos e falsos negativos (todas com teste automatizado):

- **Ausência de evidência não é evidência de ausência.** `SKIP` nunca vira aprovado; ele é `error`, `not_run`, `not_applicable` ou `inconclusive`, conforme o motivo.
- **HTTP 200 não prova vulnerabilidade.** Antes de afirmar, os testes usam **controles**: o token forjado só conta se a rota nega acesso anônimo; o BOLA só é "confirmado" se a mesma operação num recurso inexistente é recusada.
- **HTTP 401/403 não prova que o controle exista.** 401 em BOLA/BFLA significa "token não aceito" → inconclusivo.
- **Alvo fora do ar não aprova nada**: nenhuma requisição concluída ⇒ `error`, nunca `passed`.
- **SSRF sem retorno ao Sentinela** só é conclusivo se o alvo alcança o endereço de callback; caso contrário é `inconclusive`.
- **404 não é vulnerabilidade**: rota inexistente vira `inconclusive`.

## Como o estado é derivado (`app/domain/classify.py`)

| Status bruto do teste | Prova da política (`knowledge.py`) | Estado | Confiança |
|---|---|---|---|
| FAIL ou WARN | `confirmed` | `vulnerable` | Confirmada |
| FAIL ou WARN | `indicative` | `likely` | Indício |
| WARN com "404" | — | `inconclusive` | — |
| PASS | — | `passed` | — |
| SKIP | — | `error` / `not_run` / `not_applicable` / `inconclusive` | — |

Um teste pode declarar o estado explicitamente (ex.: BOLA com controle ⇒ `likely`); o classificador respeita.

## Score (`app/domain/scoring.py`)

É um **índice de conformidade nas verificações executadas**, não uma garantia. Cada categoria começa em 100.

- `vulnerable` + FAIL: perde o peso da severidade (crítica 40 · alta 25 · média 15 · baixa 7).
- `vulnerable` + WARN (alerta parcial) e `likely`: perdem metade.
- Demais estados não alteram o score.
- **Teto:** só uma falha **confirmada** limita o score — crítica a 50, alta a 70. Um indício crítico não derruba o teto.
- Veredito: ≥ 85 Conforme · 60–84 Parcialmente conforme · < 60 Não conforme.

**Política de aprovação:** reprova com qualquer vulnerabilidade **crítica confirmada**. Indícios críticos ficam em `pending`
(validação manual) e não reprovam sozinhos.

## Escopo e cobertura (`app/domain/scope.py`)

Todo scan registra o que foi e o que **não** foi executado:

- `checksPlanned` = verificações aplicáveis ao projeto (código só conta se a pasta do projeto foi informada);
- `checksExecuted` = as que tiveram estado `vulnerable`, `likely`, `passed` ou `inconclusive`;
- `coveragePct` = executadas ÷ planejadas; `notRun[]` lista cada verificação pendente **com o motivo**;
- `mode` = `external` ou `authenticated`; `limitations[]` descreve em português o que ficou de fora.

## Rotas (`app/domain/routes_view.py`)

- **Rota conhecida:** aparece na spec OpenAPI, no código ou na configuração do projeto.
- **Testada:** ao menos uma verificação obteve resposta dela. **Pendente:** conhecida, sem teste.
- **Estado da rota** = o pior estado entre as verificações que a alcançaram; "sem falha" não significa "segura".
- Caminhos sondados que não existem (ex.: `/.env` → 404) **não** são rotas.
- Rotas com nome de ação (`/createdb`, `/reset`, `/logout`…) nunca são chamadas pelo scanner; ficam como **pendentes**.
