# Contratos dos endpoints internos

Base: `http://localhost:8000`. Autenticação: `Authorization: Bearer <token>` (exceto os marcados "aberto"). Documentação interativa: `/docs`.
Erros seguem `{"detail": "mensagem"}` com 400 (validação), 401 (sessão), 403 (papel), 404, 409, 429 (muitas tentativas) ou 504 (scan excedeu o tempo).

## Autenticação e usuários
| Método e rota | Papel | Descrição |
|---|---|---|
| `GET /api/health` | aberto | saúde |
| `GET /api/auth/status` | aberto | `{authRequired, hasUsers}` |
| `POST /api/auth/bootstrap` | aberto (só 1ª vez) | cria o administrador inicial → `{token, user}` |
| `POST /api/auth/login` | aberto | `{email,password}` → `{token,user}`; bloqueio após 5 falhas em 5 min (por e-mail+IP, guardado no banco) |
| `GET /api/auth/me` | logado | usuário atual |
| `POST /api/auth/logout` | logado | 204; revoga o token (e as outras sessões) no servidor |
| `POST /api/auth/change-password` | logado | `{currentPassword,newPassword}` → `{token,user}`; as sessões antigas caem |
| `GET/POST/PUT/DELETE /api/users…` | admin | gestão; não remove nem desativa o último administrador |
| `GET /api/audit?limit=&offset=` | admin | trilha de auditoria (método, rota, status, usuário; sem corpo); total em `X-Total-Count` |
| `GET /api/admin/retention`, `POST /api/admin/retention/run` | admin | política de retenção, volumes guardados e execução imediata |
| `GET /api/metrics` | token do coletor ou admin | métricas Prometheus (`SENTINELA_METRICS_TOKEN`) |

## Projetos e credenciais
| Rota | Papel | Descrição |
|---|---|---|
| `GET/POST /api/targets`, `GET/PUT/DELETE /api/targets/{id}` | leitura: todos · escrita: analyst+ | `baseUrl` passa por `netguard`; `allowMutations` autoriza testes com escrita |
| `GET/POST/PUT/DELETE /api/targets/{id}/credentials` | admin | usuários de teste; a senha **nunca** volta (`passwordSet`) |
| `GET/PUT/DELETE /api/targets/{id}/schedule` | analyst+ | agendamento (1, 6, 12, 24 ou 168 h) |
| `PUT/DELETE /api/targets/{id}/openapi-spec` | analyst+ | importa a spec OpenAPI (corpo JSON ou YAML, até 2 MB) ou a remove; a listagem só traz o resumo (`openapiSpecSummary`) |

## Scans
| Rota | Descrição |
|---|---|
| `POST /api/scans` `{targetId \| target \| url, static, dynamic, ai, profile}` | executa e devolve o scan completo; `profile:"safe"` nunca envia escrita; 409 se o projeto já está em scan |
| `GET /api/scans/{id}/sarif` | exporta em SARIF 2.1.0 (vulnerabilidades confirmadas e prováveis) |
| `GET /api/scans?targetId=&limit=&offset=` | lista (resumo: `overall`, `verdict`, `totals.states`, `scope.{mode,coveragePct}`) |
| `GET /api/scans/{id}` | detalhe: `findings[]`, `categories[]`, `policy`, `ai[]`, **`scope`** |
| `GET /api/scans/{id}/routes` | rotas e verificações (`routes[]`, `counts`, `pendingChecks[]`, `notApplicableChecks[]`) |
| `GET /api/scans/{id}/compare` | vs. scan anterior: `new`, `fixed`, `worse`, `persisting`, **`notComparable`** |
| `DELETE /api/scans/{id}` | exclui o scan e seus achados |

### Achado (`findings[]`)
```jsonc
{
  "rowId": "uuid", "id": "D-BOLA-01",            // id = política que o gerou
  "title": "...", "category": "AUTHORIZATION", "owasp": "API1:2023",
  "severity": "CRITICAL",                          // CRITICAL|HIGH|MEDIUM|LOW|INFO
  "state": "vulnerable",                           // vulnerable|likely|inconclusive|error|passed|not_run|not_applicable
  "confidence": "confirmed",                       // confirmed|indicative|none
  "status": "FAIL",                                // legado (PASS|FAIL|WARN|SKIP)
  "asset": {"method":"PUT","path":"/users/bruno/email","httpStatus":204,"host":"..."},
  "detail": "...", "evidence": "PUT http://...\n→ HTTP 204", "recommendation": "...",
  "meta": {"headline","summary","technical","impact","exploitation","prerequisites","passWhen","failWhen",
           "limitations","severityReason","proof","scopeNote","references":[{"label","url"}]},
  "resolution": "open", "resolutionNote": null,
  "aiRec": {"gemini": {...}}
}
```

### Escopo (`scope`)
`{mode:"external"|"authenticated", credentials:{count,roles}, specFound, codeAnalyzed, mutationsAllowed, checksPlanned, checksExecuted, coveragePct, notRun:[{id,title,reason}], notApplicable:[...], limitations:[string]}`.
É `null` em scans anteriores ao registro de escopo.

## Achados, políticas e dashboard
| Rota | Descrição |
|---|---|
| `GET /api/findings?state=&confidence=&severity=&category=&resolution=&targetId=&q=` | último scan de cada projeto; por padrão só `vulnerable`/`likely` (`onlyActionable=false` traz todos) |
| `GET /api/findings/count?resolution=&targetId=` | contador leve (menu) |
| `GET/PATCH /api/findings/{rowId}` | detalhe (com `history`) e triagem (`resolution`, `resolutionNote`, `expiresInDays` 1–730 no aceite de risco; a nota é obrigatória; o aceite vence e herda para o scan seguinte) |
| `GET /api/policies/owasp` | regra de aprovação + 10 itens do OWASP com cobertura declarada e cada verificação (critérios, limitações, referências) |
| `GET /api/dashboard?targetId=` | métricas calculadas só de dados persistidos + `missing[]`/`trendNote` quando faltar dado (definições no código) |

## Integrações (admin)
`/api/integrations/{webhooks,github,slack}` (CRUD + `POST …/{id}/test`). Token do GitHub e URL do Slack são **criptografados** e devolvidos mascarados.
Destinos passam por `netguard`. O webhook genérico recebe, em todo scan, `{"event":"scan.completed","scan":{…,"scope","topFindings"[]}}`.

## Outros
`POST /api/ai/test` (testa Gemini/Groq) · `GET /api/canary/{token}` (aberto; callback do teste de SSRF).
