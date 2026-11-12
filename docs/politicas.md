# Catálogo de políticas

> Gerado por `backend/scripts/gen_policy_docs.py` a partir de `policy_catalog.py` e `knowledge.py`. Não edite à mão: altere o código e gere de novo.

Cada **política** é uma verificação com critérios explícitos. O resultado de cada uma é descrito por três eixos independentes
(ver [classificacao.md](classificacao.md)): **severidade** (impacto potencial), **confiança** (o quanto a verificação prova) e **estado** (o que aconteceu).

## Cobertura declarada do OWASP API Security Top 10 (2023)

| Item | Cobertura | Limites |
|---|---|---|
| [API1:2023 — Broken Object Level Authorization (BOLA)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | cobertura parcial | O BOLA dinâmico testa UMA rota informada no projeto, com dois usuários de teste e escrita autorizada. Rotas do tipo /recurso/{id} descobertas pela spec não são testadas automaticamente. |
| [API2:2023 — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) | cobertura parcial | Cobre JWT (alg=none, segredo fraco, expiração), rota protegida sem token, rotas da spec sem credencial e brute force no login (indício). Não testa MFA, política de senha, recuperação de conta nem fluxos OAuth ao vivo. |
| [API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) | cobertura parcial | Procura campos sensíveis por nome em respostas e testa mass assignment com UM campo e UM fluxo de cadastro. Não compara o contrato de resposta com o schema da spec. |
| [API4:2023 — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | cobertura parcial | Só mede 429 em uma rajada de 20 requisições (indício). Não testa quotas por usuário, paginação sem limite nem endpoints custosos. |
| [API5:2023 — Broken Function Level Authorization (BFLA)](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) | cobertura parcial | Testa as rotas administrativas informadas e as que a spec nomeia como admin/internal/debug (apenas GET), com usuário comum. Funções administrativas com outros nomes não são vistas. |
| [API6:2023 — Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | cobertura parcial | Avalia a documentação de limites em fluxos sensíveis e o brute force no login. Não simula abuso de regra de negócio (ex.: limite de transferências por conta). |
| [API7:2023 — Server Side Request Forgery (SSRF)](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) | cobertura parcial | SSRF por callback em parâmetros GET com nome de URL. Não cobre parâmetros em corpo JSON, cabeçalhos nem SSRF cego sem retorno ao Sentinela. Exige que o alvo alcance o Sentinela. |
| [API8:2023 — Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/) | cobertura ampla | Cabeçalhos de segurança, CORS, TLS, divulgação de versão, rotas de debug e, com código, segredos, TLS desligado e modo debug. Não avalia versão de TLS, cifras nem mensagens de erro verbosas. |
| [API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) | cobertura parcial | Lista endpoints do código e da spec e procura rotas de debug expostas. Não detecta versões antigas (v1, v2) esquecidas nem hosts não documentados. |
| [API10:2023 — Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/) | sem verificação | Ainda sem verificação de como a API valida dados vindos de APIs de terceiros que ela consome. A verificação de assinatura de webhooks está listada em Autenticação (API2). |

Nenhum item é marcado como coberto só por existir uma política com o nome correspondente.

## API1:2023 — Broken Object Level Authorization (BOLA)

Um usuário acessa objetos de outro manipulando o identificador. Exige checar o dono (userId) em toda leitura/escrita de objeto.

### `D-BOLA-A1` — BOLA automático — rotas /recurso/{id} negam o objeto de outro usuário

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** Detectar acesso indevido de leitura entre usuários em rotas com identificador.
- **Como testa:** Descobre na spec as rotas GET com identificador no caminho, confirma que o dono lê o próprio recurso e repete a chamada com outro usuário comum, com controle de ID inexistente.
- **Pré-requisitos:** Spec com rotas /recurso/{id}, dois usuários de teste de papel comum e o ID de um recurso real do segundo usuário (campo 'ID do recurso' em Acesso).
- **Aprova quando:** Todas as rotas testadas negam o usuário atacante (401, 403 ou 404).
- **Reprova quando:** Ao menos uma rota devolve 2xx ao atacante para o recurso do dono, e o controle com ID inexistente não devolve 2xx.
- **Cenário de exploração:** Um usuário autenticado troca o identificador na URL pelo de outra pessoa e repete a requisição.
- **Impacto:** Leitura de dados de outros clientes por qualquer usuário autenticado (confidencialidade). Em contexto bancário, expõe contas, extratos e dados pessoais de terceiros.
- **Por que esta severidade:** Crítica: afeta dados de terceiros e é explorável por qualquer usuário autenticado.
- **Limitações:** Só leitura (GET) e só rotas com um parâmetro de caminho. Rotas em que o ID informado não pertence ao dono são ignoradas. Não cobre escrita; para isso use o BOLA dinâmico.
- **Referências:** [OWASP API Security Top 10 2023 — API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-285](https://cwe.mitre.org/data/definitions/285.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_BOLA_A1_rota_com_id_vulneravel_e_confirmada`, `test_policies_more_dynamic.py::test_D_BOLA_A1_rota_segura_passa`, `test_policies_more_dynamic.py::test_D_BOLA_A1_sem_id_do_recurso_nao_executa`, `test_policies_more_dynamic.py::test_D_BOLA_A1_nao_aparece_sem_rota_com_id_na_spec`

### `S-BOLA-01` — Autorização em nível de objeto (BOLA)

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Consultas a objetos com dono podem não filtrar pelo usuário.
- **Como testa:** Lê o schema/rotas e procura modelos com dono (userId) acessados sem filtro pelo dono.
- **Pré-requisitos:** Código-fonte do projeto acessível e modelo com campo userId (Prisma).
- **Aprova quando:** Todas as operações por ID incluem o dono na cláusula where, ou a posse é validada antes.
- **Reprova quando:** Operações por ID sem filtro pelo dono e sem validação prévia identificável.
- **Cenário de exploração:** Mesmo cenário do BOLA dinâmico; aqui apenas se aponta o ponto do código.
- **Impacto:** Se confirmado, permite acesso a objetos de outros usuários (ver BOLA dinâmico).
- **Por que esta severidade:** Média: é um indício no código; a confirmação depende do teste dinâmico.
- **Limitações:** Heurística por padrão de texto, só para Prisma/Next.js. Posse validada em outra camada gera falso positivo.
- **Referências:** [OWASP API Security Top 10 2023 — API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`, `test_static_rules.py::test_S_BOLA_01_aponta_operacao_por_id_sem_filtro_de_dono`, `test_static_rules.py::test_regras_estaticas_por_indicio_nunca_reprovam_a_politica_sozinhas`, `test_static_rules.py::test_S_DISC_01_lista_rotas_do_codigo_e_aponta_as_fora_do_inventario`

### `D-BOLA-01` — BOLA dinâmico — agir sobre o objeto de outro usuário

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** Detectar acesso indevido entre usuários do mesmo papel.
- **Como testa:** Cria dois usuários de teste, o usuário B tenta ler/alterar um objeto do usuário A. Reprova se a API deixar.
- **Pré-requisitos:** Dois usuários de teste do mesmo papel; rota e método do recurso configurados; ambiente que permita testes com escrita.
- **Aprova quando:** A operação de B no recurso de A é negada (401, 403 ou 404).
- **Reprova quando:** A operação de B no recurso de A retorna 2xx.
- **Cenário de exploração:** Um usuário autenticado troca o identificador do recurso na rota (por exemplo, o ID da conta) pelo de outra pessoa e repete a requisição.
- **Impacto:** Leitura ou alteração de dados de outros clientes (confidencialidade e integridade). Em contexto bancário, expõe ou modifica contas e dados pessoais de terceiros.
- **Por que esta severidade:** Crítica: afeta dados de terceiros e é explorável por qualquer usuário autenticado.
- **Limitações:** Não confere se o dado foi de fato alterado (apenas o código de resposta). Cobre uma única rota configurada; outras rotas com o mesmo defeito não são detectadas.
- **Referências:** [OWASP API Security Top 10 2023 — API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-285](https://cwe.mitre.org/data/definitions/285.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_o_que_a_api_devolve_e_o_que_o_banco_guarda`, `test_api_modes_and_persistence.py::test_filtros_de_achados_por_estado_e_confianca`, `test_api_modes_and_persistence.py::test_execucoes_nao_sobrescrevem_umas_as_outras`, `test_api_modes_and_persistence.py::test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes`, `test_api_modes_and_persistence.py::test_o_score_nao_e_igual_por_coincidencia_de_teto`, `test_api_modes_and_persistence.py::test_comparacao_nao_trata_nao_executado_como_corrigido`, `test_api_modes_and_persistence.py::test_token_do_github_e_url_do_slack_ficam_criptografados`, `test_classification_and_scoring.py::test_estado_explicito_do_probe_e_respeitado`, `test_classification_and_scoring.py::test_ativo_e_http_sao_extraidos_da_evidencia`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_D_SPEC_02_mascara_valores_sensiveis_na_evidencia`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`, `test_policies_vs_lab.py::test_D_BOLA_01_api_que_ignora_o_id_e_apenas_indicio`, `test_policies_vs_lab.py::test_D_BOLA_01_e_D_BFLA_01_401_nao_e_aprovacao`, `test_policies_vs_lab.py::test_D_BFLA_A1_401_em_todas_as_rotas_e_inconclusivo`, `test_policies_vs_lab.py::test_sem_autorizacao_de_escrita_nenhum_metodo_que_altera_dados_e_enviado`, `test_policies_vs_lab.py::test_regressao_scanner_nunca_chama_rota_com_nome_de_acao`, `test_policies_vs_lab.py::test_D_BOLA_01_com_escrita_autorizada_executa`, `test_policies_vs_lab.py::test_login_de_teste_invalido_gera_erro_e_nao_aprova_verificacoes_autenticadas`, `test_routes_and_dashboard.py::test_rotas_scan_externo_lista_verificacoes_pendentes_com_motivo`, `test_routes_and_dashboard.py::test_dashboard_numeros_batem_com_o_ultimo_scan_de_cada_projeto`

### `D-AUTHZ-0N` — Acesso não autenticado negado nas rotas configuradas

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** Uma rota declarada como protegida responde sem sessão.
- **Como testa:** Acessa cada rota sensível do alvo sem sessão; deve responder 401/403 (nunca 200).
- **Pré-requisitos:** Lista de rotas protegidas informada no projeto.
- **Aprova quando:** Resposta 401/403 ou redirecionamento para login.
- **Reprova quando:** Resposta 2xx sem sessão. (404 vira alerta: rota possivelmente inexistente neste ambiente.)
- **Cenário de exploração:** Acesso direto à URL, sem autenticação.
- **Impacto:** Exposição de dados ou funções que deveriam exigir login.
- **Por que esta severidade:** Crítica: dado potencialmente acessível sem autenticação.
- **Limitações:** Depende de a rota realmente exigir login na intenção do projeto; rota pública listada por engano gera falso positivo.
- **Referências:** [OWASP API Security Top 10 2023 — API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_catalogo_de_politicas_lista_todas_as_verificacoes_executadas`, `test_classification_and_scoring.py::test_http_404_em_alerta_e_inconclusivo_nao_vulnerabilidade`, `test_classification_and_scoring.py::test_estado_explicito_do_probe_e_respeitado`, `test_policies_more_dynamic.py::test_D_AUTHZ_0N_rota_declarada_protegida_que_responde_sem_sessao`, `test_policies_more_dynamic.py::test_D_AUTHZ_0N_rota_inexistente_e_inconclusiva_nao_vulneravel`, `test_policies_more_dynamic.py::test_D_MASS_01_campo_privilegiado_aceito_no_cadastro`, `test_routes_and_dashboard.py::test_rotas_e_verificacoes_separam_estados_e_os_totais_batem`

## API2:2023 — Broken Authentication

Falhas em login, tokens ou sessões que permitem assumir a identidade de outro (JWT mal validado, tokens sem expiração, credenciais fracas).

### `D-JWT-01` — JWT — alg=none não é aceito

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** O servidor aceita token JWT sem assinatura (alg=none).
- **Como testa:** Forja um token com alg=none (sem assinatura) e tenta acessar rota protegida. Reprova se aceitar.
- **Pré-requisitos:** Login funcional e rota protegida configurada.
- **Aprova quando:** A rota protegida rejeita o token forjado.
- **Reprova quando:** A rota protegida responde 200 ao token forjado.
- **Cenário de exploração:** O atacante cria um JWT com o usuário desejado, sem conhecer a chave, e o apresenta ao servidor.
- **Impacto:** Qualquer pessoa forja um token e assume a identidade de qualquer usuário.
- **Por que esta severidade:** Crítica: quebra total da autenticação.
- **Limitações:** Valida apenas a variante alg=none; outras falhas de verificação (confusão de algoritmo RS256/HS256) não são testadas.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes`, `test_api_modes_and_persistence.py::test_o_score_nao_e_igual_por_coincidencia_de_teto`, `test_classification_and_scoring.py::test_falha_com_prova_direta_e_vulneravel_confirmada`, `test_classification_and_scoring.py::test_falha_de_verificacao_indicativa_vira_provavel_e_nao_confirmada`, `test_classification_and_scoring.py::test_so_falha_confirmada_aplica_o_teto_de_score`, `test_classification_and_scoring.py::test_indicio_pesa_menos_que_prova`, `test_classification_and_scoring.py::test_politica_reprova_so_com_critico_confirmado`, `test_classification_and_scoring.py::test_toda_verificacao_do_catalogo_tem_texto_editorial_completo`, `test_policies_more_dynamic.py::test_D_JWT_01_evidencia_mostra_requisicao_e_controle`, `test_policies_more_dynamic.py::test_D_JWT_02_nunca_registra_o_segredo_quebrado`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`, `test_policies_vs_lab.py::test_D_BOLA_01_api_que_ignora_o_id_e_apenas_indicio`, `test_policies_vs_lab.py::test_login_de_teste_invalido_gera_erro_e_nao_aprova_verificacoes_autenticadas`

### `D-JWT-02` — JWT — segredo HMAC não é trivial

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** O segredo de assinatura do JWT é fraco.
- **Como testa:** Tenta quebrar a assinatura HS256/384/512 com uma lista de segredos fracos comuns.
- **Pré-requisitos:** Token HMAC obtido no login.
- **Aprova quando:** Nenhum segredo da lista reproduz a assinatura (ou o algoritmo não é HMAC — teste não aplicável).
- **Reprova quando:** Um segredo da lista reproduz a assinatura.
- **Cenário de exploração:** Ataque offline de dicionário sobre um token capturado.
- **Impacto:** Com o segredo, o atacante forja tokens válidos para qualquer usuário.
- **Por que esta severidade:** Crítica: permite forjar identidade.
- **Limitações:** A lista é curta. Aprovação não prova que o segredo seja forte, apenas que não é um dos valores comuns testados.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-521](https://cwe.mitre.org/data/definitions/521.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes`, `test_policies_more_dynamic.py::test_D_JWT_02_segredo_fraco_e_detectado_e_segredo_forte_passa`, `test_policies_more_dynamic.py::test_D_EXPOSE_01_campo_sensivel_na_resposta_autenticada`, `test_policies_more_dynamic.py::test_D_JWT_02_nunca_registra_o_segredo_quebrado`, `test_policies_more_dynamic.py::test_D_BOLA_A1_rota_com_id_vulneravel_e_confirmada`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`

### `D-JWT-03` — JWT possui claim de expiração (exp)

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** O token não possui data de expiração (exp).
- **Como testa:** Decodifica o token recebido no login e verifica se existe o claim exp.
- **Pré-requisitos:** Token JWT obtido no login.
- **Aprova quando:** O token traz exp.
- **Reprova quando:** O token não traz exp.
- **Cenário de exploração:** Reaproveitamento de um token vazado, sem limite de tempo.
- **Impacto:** Token roubado permanece válido indefinidamente.
- **Por que esta severidade:** Média: amplia a janela de abuso de tokens vazados, mas não é exploração direta.
- **Limitações:** Não avalia se o servidor aplica o exp, nem se o prazo é adequado.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-613](https://cwe.mitre.org/data/definitions/613.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_JWT_03_token_sem_exp_e_vulneravel_de_severidade_media`, `test_policies_more_dynamic.py::test_D_JWT_02_segredo_fraco_e_detectado_e_segredo_forte_passa`

### `D-AUTH-01` — Rota protegida exige token válido

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** A rota protegida aceita acesso sem token ou com token inválido.
- **Como testa:** Chama a rota protegida sem token e com token inválido; ambas devem responder 401/403.
- **Pré-requisitos:** Rota protegida configurada.
- **Aprova quando:** Ambas as chamadas retornam 401 ou 403.
- **Reprova quando:** Alguma das chamadas retorna resposta diferente de 401/403.
- **Cenário de exploração:** Requisição direta à rota, sem login.
- **Impacto:** Dados do usuário acessíveis sem autenticação.
- **Por que esta severidade:** Alta: falha de autenticação em rota que deveria ser protegida.
- **Limitações:** Testa uma única rota. Respostas como 302 ou 404 geram falha e exigem leitura da evidência.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-287](https://cwe.mitre.org/data/definitions/287.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes`, `test_policies_more_dynamic.py::test_D_AUTH_01_rota_protegida_aberta_reprova`, `test_policies_more_dynamic.py::test_D_AUTHZ_0N_rota_declarada_protegida_que_responde_sem_sessao`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`

### `S-AUTHZ-02` — Rotas de API verificam autenticação/assinatura

- **Tipo:** análise de código · **Severidade:** CRITICAL · **Prova:** indício
- **Objetivo:** Rotas de API sem verificação de autenticação identificável no código.
- **Como testa:** Varre as rotas de API no código e aponta as que não chamam nenhuma verificação de sessão/assinatura.
- **Pré-requisitos:** Código-fonte do projeto (Next.js).
- **Aprova quando:** Toda rota de API contém verificação reconhecida ou é coberta por middleware.
- **Reprova quando:** Rota sem nenhuma verificação reconhecida.
- **Cenário de exploração:** Acesso direto à rota.
- **Impacto:** Se confirmado, rota acessível sem login.
- **Por que esta severidade:** Crítica se confirmada; o achado estático é um indício.
- **Limitações:** Padrões de texto específicos; outras formas de proteger a rota geram falso positivo.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- **Testes automatizados:** `test_classification_and_scoring.py::test_falha_indicativa_com_status_fail_e_rebaixada_para_provavel`, `test_classification_and_scoring.py::test_http_404_em_alerta_e_inconclusivo_nao_vulnerabilidade`, `test_classification_and_scoring.py::test_so_falha_confirmada_aplica_o_teto_de_score`, `test_classification_and_scoring.py::test_indicio_pesa_menos_que_prova`, `test_classification_and_scoring.py::test_politica_reprova_so_com_critico_confirmado`, `test_classification_and_scoring.py::test_toda_verificacao_do_catalogo_tem_texto_editorial_completo`, `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`, `test_static_rules.py::test_regras_estaticas_por_indicio_nunca_reprovam_a_politica_sozinhas`, `test_static_rules.py::test_S_DISC_01_lista_rotas_do_codigo_e_aponta_as_fora_do_inventario`

### `S-TOKEN-01` — Cookies de sessão com flags de proteção

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** prova direta
- **Objetivo:** Cookies de sessão sem todas as flags de proteção.
- **Como testa:** Procura HttpOnly, Secure e SameSite na configuração de cookies de sessão.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** As três flags estão presentes.
- **Reprova quando:** Alguma flag ausente.
- **Cenário de exploração:** XSS lê o cookie; ou interceptação em HTTP.
- **Impacto:** Roubo de sessão por script injetado ou envio em tráfego não cifrado.
- **Por que esta severidade:** Alta: afeta a proteção da sessão.
- **Limitações:** Detecção por texto no código; configuração feita por proxy/framework pode não ser vista.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html), [CWE-614](https://cwe.mitre.org/data/definitions/614.html), [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-TOKEN-02` — Tokens de recuperação expiram e são de uso único

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Tokens de recuperação de senha podem não expirar nem ser de uso único.
- **Como testa:** Verifica expiração e remoção do token de reset de senha após o uso.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** Há expiração e invalidação após o uso.
- **Reprova quando:** Ausência identificável.
- **Cenário de exploração:** Uso de um link antigo para tomar a conta.
- **Impacto:** Reaproveitamento de links de redefinição de senha.
- **Por que esta severidade:** Média.
- **Limitações:** Heurística textual.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-640](https://cwe.mitre.org/data/definitions/640.html), [CWE-613](https://cwe.mitre.org/data/definitions/613.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-TOKEN-03` — DPoP — prova de posse do token

- **Tipo:** análise de código · **Severidade:** LOW · **Prova:** indício
- **Objetivo:** Tokens não são vinculados a uma chave do cliente (DPoP).
- **Como testa:** Procura vínculo do token a uma chave do cliente (sender-constrained tokens).
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** DPoP detectado.
- **Reprova quando:** DPoP não detectado.
- **Cenário de exploração:** Replay de token capturado.
- **Impacto:** Token vazado pode ser usado por qualquer parte.
- **Por que esta severidade:** Baixa: endurecimento adicional.
- **Limitações:** DPoP é uma proteção adicional, não um requisito universal; trate como recomendação.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-294](https://cwe.mitre.org/data/definitions/294.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-OIDC-01` — OAuth 2.0 / OpenID Connect configurado

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** indício
- **Objetivo:** Não foi encontrada configuração de OAuth 2.0 / OpenID Connect.
- **Como testa:** Detecta provedor OAuth/OIDC e persistência de tokens no código.
- **Pré-requisitos:** Código-fonte do projeto (Next.js).
- **Aprova quando:** Provedor OAuth/OIDC detectado.
- **Reprova quando:** Nenhum provedor detectado.
- **Cenário de exploração:** Não se aplica a exploração direta.
- **Impacto:** Autenticação própria tende a ser menos robusta que provedor estabelecido.
- **Por que esta severidade:** Alta como recomendação de arquitetura; não prova vulnerabilidade.
- **Limitações:** Sistemas que usam outro mecanismo legítimo (mTLS, SAML) aparecem como falha.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-287](https://cwe.mitre.org/data/definitions/287.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-OIDC-02` — PKCE e state no fluxo de autorização

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Fluxo OAuth sem PKCE e state identificáveis.
- **Como testa:** Confirma PKCE + state no fluxo (ou biblioteca que os aplica por padrão).
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** PKCE e state presentes.
- **Reprova quando:** Ausência identificável.
- **Cenário de exploração:** Injeção de um código de autorização do atacante na sessão da vítima.
- **Impacto:** Interceptação do código de autorização ou CSRF no login.
- **Por que esta severidade:** Média.
- **Limitações:** Heurística textual.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `D-OIDC-01` — Provedores de autenticação disponíveis

- **Tipo:** teste ao vivo · **Severidade:** INFO · **Prova:** indício
- **Objetivo:** Consulta ao endpoint de provedores de autenticação.
- **Como testa:** Consulta o endpoint de provedores de autenticação do alvo.
- **Pré-requisitos:** Rota de provedores configurada no projeto.
- **Aprova quando:** Resposta 200.
- **Reprova quando:** Resposta diferente de 200 gera alerta.
- **Cenário de exploração:** Não se aplica.
- **Impacto:** Informativo.
- **Por que esta severidade:** Informativa.
- **Limitações:** Apenas informativa.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_OIDC_01_endpoint_de_provedores`, `test_policies_more_dynamic.py::test_D_FLOW_02_login_com_e_sem_limite_de_tentativas`

### `S-INPUT-02` — Senhas com hash forte (bcrypt)

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** indício
- **Objetivo:** Armazenamento de senha sem algoritmo forte identificado.
- **Como testa:** Procura bcrypt/argon2/scrypt no código de cadastro e login.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** Algoritmo forte detectado.
- **Reprova quando:** Nenhum algoritmo forte detectado.
- **Cenário de exploração:** Ataque de força bruta offline sobre hashes.
- **Impacto:** Senhas vazadas do banco seriam quebradas com facilidade.
- **Por que esta severidade:** Alta.
- **Limitações:** Heurística textual; bibliotecas de identidade externas podem cuidar disso sem aparecer no código.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-916](https://cwe.mitre.org/data/definitions/916.html), [CWE-328](https://cwe.mitre.org/data/definitions/328.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-AUTHZ-01` — Middleware protege as rotas da aplicação

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** indício
- **Objetivo:** Não foi identificado middleware global de proteção das rotas.
- **Como testa:** Confirma que existe middleware global de sessão com matcher cobrindo as rotas.
- **Pré-requisitos:** Código-fonte do projeto (Next.js).
- **Aprova quando:** Middleware com matcher detectado.
- **Reprova quando:** Não detectado.
- **Cenário de exploração:** Acesso a rota esquecida.
- **Impacto:** Rotas novas podem ficar desprotegidas por padrão.
- **Por que esta severidade:** Alta como recomendação.
- **Limitações:** Heurística textual específica de Next.js.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`, `test_static_rules.py::test_regras_estaticas_por_indicio_nunca_reprovam_a_politica_sozinhas`, `test_static_rules.py::test_S_DISC_01_lista_rotas_do_codigo_e_aponta_as_fora_do_inventario`

### `D-SPEC-01` — Rotas protegidas pela spec negam acesso anônimo

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** Rotas que a spec declara protegidas respondem sem credencial.
- **Como testa:** Lê a spec OpenAPI e chama, sem credencial, as rotas GET que ela declara protegidas; 2xx reprova. Rotas com nome de ação (create, delete, reset, logout…) nunca são chamadas.
- **Pré-requisitos:** Spec OpenAPI acessível.
- **Aprova quando:** Todas negam acesso anônimo.
- **Reprova quando:** Alguma rota protegida responde 2xx sem credencial.
- **Cenário de exploração:** Acesso direto sem login.
- **Impacto:** A proteção declarada não é aplicada pelo servidor.
- **Por que esta severidade:** Alta: contradiz o contrato declarado da API.
- **Limitações:** Só GET sem parâmetro de caminho e sem nome de ação. A spec pode estar desatualizada em relação ao serviço.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_DISC_01_spec_ausente_e_nao_executado_nao_aprovado`, `test_policies_more_dynamic.py::test_D_SOAP_01_e_D_SOAP_02_wsdl_exposto_e_politica_ws_security`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`

### `S-SEC-04` — Hash de senha não usa algoritmo fraco

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** prova direta
- **Objetivo:** Hash fraco aplicado a senhas.
- **Como testa:** Procura MD5/SHA-1 aplicados a senhas em várias linguagens.
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Força bruta offline.
- **Impacto:** Senhas vazadas são quebradas rapidamente.
- **Por que esta severidade:** Alta.
- **Limitações:** Padrão por texto; MD5 usado para outra finalidade pode ser acusado.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-328](https://cwe.mitre.org/data/definitions/328.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`

### `S-SEC-07` — Tokens JWT são sempre verificados

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** prova direta
- **Objetivo:** JWT com verificação de assinatura ou expiração desativada.
- **Como testa:** Procura verificação de assinatura desligada, algoritmo 'none' e expiração ignorada.
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Apresentar token adulterado.
- **Impacto:** Tokens forjados ou expirados são aceitos.
- **Por que esta severidade:** Alta.
- **Limitações:** Padrão por texto.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`

### `D-SOAP-02` — Serviço SOAP declara política WS-Security

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** indício
- **Objetivo:** O serviço SOAP não declara política WS-Security.
- **Como testa:** Verifica no WSDL a presença de política WS-Security (UsernameToken, assinatura/criptografia XML).
- **Pré-requisitos:** WSDL acessível.
- **Aprova quando:** Política WS-Security declarada.
- **Reprova quando:** Nenhuma declarada.
- **Cenário de exploração:** Interceptação ou adulteração da mensagem.
- **Impacto:** Mensagens SOAP sem integridade ou confidencialidade de mensagem.
- **Por que esta severidade:** Alta como recomendação.
- **Limitações:** A segurança pode ser aplicada na camada de transporte (TLS) sem constar no WSDL.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_SOAP_01_e_D_SOAP_02_wsdl_exposto_e_politica_ws_security`, `test_policies_more_dynamic.py::test_D_BFLA_0N_e_D_BFLA_A1_usuario_admin_nao_e_o_alvo_do_teste`

### `S-INTEG-01` — Webhooks verificam assinatura da requisição

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** indício
- **Objetivo:** Webhooks recebidos sem verificação de assinatura identificável.
- **Como testa:** Procura validação de assinatura do provedor antes de processar o webhook.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** Verificação de assinatura detectada.
- **Reprova quando:** Nenhuma verificação detectada.
- **Cenário de exploração:** O atacante envia POST forjado ao endpoint do webhook.
- **Impacto:** Requisições forjadas acionam ações de negócio.
- **Por que esta severidade:** Alta.
- **Limitações:** Heurística textual.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `D-INTEG-01` — Webhook rejeita requisição sem assinatura

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** O webhook aceita requisição sem assinatura.
- **Como testa:** Envia um POST forjado (formato Twilio/WhatsApp, sem x-twilio-signature) ao webhook configurado; deve responder 403.
- **Pré-requisitos:** Rota de webhook configurada.
- **Aprova quando:** Resposta 403.
- **Reprova quando:** Qualquer resposta que não seja 403 (404 vira alerta: rota possivelmente inexistente).
- **Cenário de exploração:** POST direto ao endpoint.
- **Impacto:** Qualquer pessoa aciona o processamento de eventos falsos.
- **Por que esta severidade:** Alta.
- **Limitações:** O formato do corpo é o do provedor padrão do projeto de exemplo; outros provedores podem exigir outro formato.
- **Referências:** [OWASP API Security Top 10 2023 — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_INTEG_01_webhook_sem_assinatura`, `test_policies_more_dynamic.py::test_D_INTEG_02_cron_sem_segredo`

## API3:2023 — Broken Object Property Level Authorization

Leitura ou escrita de propriedades que o usuário não deveria ver/editar (excessive data exposure + mass assignment).

### `D-EXPOSE-01` — Resposta não expõe campos sensíveis

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** A resposta autenticada devolve campos sensíveis.
- **Como testa:** Lê a resposta de rota autenticada e procura campos como password, hash, token, secret.
- **Pré-requisitos:** Login e rota protegida configurados.
- **Aprova quando:** Nenhum campo sensível com valor.
- **Reprova quando:** Campo sensível com valor na resposta.
- **Cenário de exploração:** Leitura da resposta normal da API.
- **Impacto:** Vazamento de credenciais ou dados pessoais em respostas comuns.
- **Por que esta severidade:** Alta: expõe dados sensíveis a quem pode chamar a rota.
- **Limitações:** Verifica apenas uma rota e pelos nomes dos campos.
- **Referências:** [OWASP API Security Top 10 2023 — API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-213](https://cwe.mitre.org/data/definitions/213.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes`, `test_policies_more_dynamic.py::test_D_EXPOSE_01_campo_sensivel_na_resposta_autenticada`, `test_policies_more_dynamic.py::test_D_AUTH_01_rota_protegida_aberta_reprova`

### `D-MASS-01` — Mass assignment — atribuição de campo privilegiado

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** O cadastro aceita campo privilegiado enviado pelo cliente (mass assignment).
- **Como testa:** Envia campos privilegiados (ex.: role=admin) no cadastro e verifica se foram aceitos.
- **Pré-requisitos:** Rota de cadastro, campo privilegiado e caminho de verificação configurados; ambiente que permita criar contas.
- **Aprova quando:** O campo não é persistido.
- **Reprova quando:** O usuário volta com o privilégio atribuído.
- **Cenário de exploração:** O atacante inclui o campo privilegiado no corpo do cadastro.
- **Impacto:** Escalada de privilégio por qualquer pessoa que se cadastre.
- **Por que esta severidade:** Alta: escalada de privilégio.
- **Limitações:** Testa um único campo e um único fluxo de cadastro.
- **Referências:** [OWASP API Security Top 10 2023 — API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [CWE-915](https://cwe.mitre.org/data/definitions/915.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_MASS_01_campo_privilegiado_aceito_no_cadastro`, `test_policies_more_dynamic.py::test_D_MASS_01_sem_autorizacao_de_escrita_nao_cria_conta_no_alvo`, `test_policies_more_dynamic.py::test_D_INFO_01_divulgacao_de_tecnologia_e_versao`

### `S-INPUT-01` — Validação de esquema na entrada

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Entradas podem não ser validadas por esquema.
- **Como testa:** Procura validação de esquema (Zod, Pydantic, Joi…) antes de a entrada tocar o banco.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** Validação de esquema detectada.
- **Reprova quando:** Não detectada.
- **Cenário de exploração:** Envio de corpos inesperados.
- **Impacto:** Dados malformados chegam à lógica e ao banco.
- **Por que esta severidade:** Média.
- **Limitações:** Heurística textual.
- **Referências:** [OWASP API Security Top 10 2023 — API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `D-SPEC-02` — Rotas públicas não expõem dados sensíveis

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta
- **Objetivo:** Rota pública devolve campos sensíveis.
- **Como testa:** Chama as rotas GET sem 'security' e procura campos como senha, CPF, token na resposta (valores mascarados na evidência).
- **Pré-requisitos:** Spec OpenAPI acessível.
- **Aprova quando:** Nenhuma rota pública devolve campos sensíveis.
- **Reprova quando:** Rota pública com campo sensível preenchido.
- **Cenário de exploração:** Qualquer pessoa chama a rota e lê os dados.
- **Impacto:** Dados pessoais ou credenciais acessíveis sem autenticação.
- **Por que esta severidade:** Crítica: dado sensível acessível sem autenticação.
- **Limitações:** Só rotas GET sem parâmetro de caminho e sem nome de ação. Detecta por nome de campo; dado sensível com nome genérico não é visto.
- **Referências:** [OWASP API Security Top 10 2023 — API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
- **Testes automatizados:** `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_D_SPEC_02_mascara_valores_sensiveis_na_evidencia`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_routes_and_dashboard.py::test_rotas_e_verificacoes_separam_estados_e_os_totais_batem`

## API4:2023 — Unrestricted Resource Consumption

Ausência de rate limiting/quotas, abrindo espaço para abuso, DoS e custo (endpoints caros sem limite).

### `D-RATE-01` — Rate limiting sob rajada de requisições

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Não houve limitação de requisições em uma rajada de 20.
- **Como testa:** Dispara 20 requisições em rajada e espera receber 429 (throttling) em alguma delas.
- **Pré-requisitos:** Alvo respondendo.
- **Aprova quando:** Alguma resposta 429 (throttling) na rajada.
- **Reprova quando:** Nenhuma das 20 requisições foi limitada.
- **Cenário de exploração:** Automação de requisições em volume.
- **Impacto:** Abuso de recursos, força bruta e custo elevado.
- **Por que esta severidade:** Média: ausência de limite não é, isoladamente, exploração.
- **Limitações:** 20 requisições podem estar abaixo do limite real do serviço; a raiz pode não ser a rota limitada. É indício, não prova.
- **Referências:** [OWASP API Security Top 10 2023 — API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [CWE-770](https://cwe.mitre.org/data/definitions/770.html)
- **Testes automatizados:** `test_classification_and_scoring.py::test_falha_de_verificacao_indicativa_vira_provavel_e_nao_confirmada`, `test_classification_and_scoring.py::test_falha_indicativa_com_status_fail_e_rebaixada_para_provavel`, `test_policies_vs_lab.py::test_D_RATE_01_rota_que_sempre_nega_nao_mede_rate_limit`, `test_policies_vs_lab.py::test_D_RATE_01_sem_429_na_raiz_e_apenas_indicio_e_com_429_passa`, `test_policies_vs_lab.py::test_D_CORS_01_sem_cabecalho_cors_e_aprovado_nao_pulado`, `test_routes_and_dashboard.py::test_rotas_e_verificacoes_separam_estados_e_os_totais_batem`

## API5:2023 — Broken Function Level Authorization (BFLA)

Falta de checagem de papel/permissão em funções (usuário comum alcançando rota administrativa).

### `D-BFLA-0N` — BFLA — usuário comum não acessa função administrativa

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** Usuário comum executa função administrativa configurada.
- **Como testa:** Loga com um usuário de papel comum e chama as rotas administrativas configuradas; qualquer 2xx reprova.
- **Pré-requisitos:** Usuário comum cadastrado; rota administrativa informada; ambiente que permita testes com escrita se o método não for GET.
- **Aprova quando:** A rota nega o usuário comum.
- **Reprova quando:** A rota responde 2xx ao usuário comum.
- **Cenário de exploração:** Chamada direta à URL administrativa com o token de um usuário comum.
- **Impacto:** Usuário comum realiza ações privilegiadas (administração, exclusão, relatórios).
- **Por que esta severidade:** Alta: escalada vertical de privilégio.
- **Limitações:** Cobre só as rotas informadas. Resposta 401 pode indicar que a rota nem chegou à checagem de papel.
- **Referências:** [OWASP API Security Top 10 2023 — API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/), [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- **Testes automatizados:** `test_api_modes_and_persistence.py::test_scan_externo_e_autenticado_declaram_escopo_e_cobertura_diferentes`, `test_api_modes_and_persistence.py::test_catalogo_de_politicas_lista_todas_as_verificacoes_executadas`, `test_policies_more_dynamic.py::test_D_BFLA_0N_e_D_BFLA_A1_usuario_admin_nao_e_o_alvo_do_teste`, `test_policies_more_dynamic.py::test_D_JWT_01_evidencia_mostra_requisicao_e_controle`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`, `test_policies_vs_lab.py::test_D_BOLA_01_e_D_BFLA_01_401_nao_e_aprovacao`, `test_policies_vs_lab.py::test_D_BFLA_A1_401_em_todas_as_rotas_e_inconclusivo`, `test_policies_vs_lab.py::test_sem_autorizacao_de_escrita_nenhum_metodo_que_altera_dados_e_enviado`, `test_policies_vs_lab.py::test_regressao_scanner_nunca_chama_rota_com_nome_de_acao`

### `D-BFLA-A1` — BFLA automático — rotas administrativas da spec negam usuário comum

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** Rotas administrativas descobertas pela spec respondem a um usuário comum.
- **Como testa:** Descobre na spec as rotas GET com 'admin', 'internal' ou 'debug' e as chama com um usuário comum; qualquer 2xx reprova.
- **Pré-requisitos:** Spec acessível e usuário comum cadastrado.
- **Aprova quando:** Todas as rotas administrativas negam o usuário comum.
- **Reprova quando:** Ao menos uma rota responde 2xx ao usuário comum.
- **Cenário de exploração:** Chamada direta à rota.
- **Impacto:** Funções administrativas acessíveis a qualquer usuário autenticado.
- **Por que esta severidade:** Alta.
- **Limitações:** Só GET, sem parâmetro de caminho. A classificação 'administrativa' é por nome; rotas administrativas com outros nomes não são vistas.
- **Referências:** [OWASP API Security Top 10 2023 — API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/), [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_BFLA_0N_e_D_BFLA_A1_usuario_admin_nao_e_o_alvo_do_teste`, `test_policies_more_dynamic.py::test_D_JWT_01_evidencia_mostra_requisicao_e_controle`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_D_BFLA_A1_401_em_todas_as_rotas_e_inconclusivo`, `test_policies_vs_lab.py::test_D_RATE_01_rota_que_sempre_nega_nao_mede_rate_limit`

### `D-INTEG-02` — Endpoint de cron/interno exige segredo

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** indício · **Requer configuração do projeto**
- **Objetivo:** Endpoint interno (cron) responde sem o segredo.
- **Como testa:** Chama o endpoint de cron configurado sem o segredo Bearer; 401/403 passa, qualquer outro código gera alerta.
- **Pré-requisitos:** Rota de cron configurada.
- **Aprova quando:** Resposta 401 ou 403.
- **Reprova quando:** Outra resposta gera alerta (404 = rota possivelmente inexistente).
- **Cenário de exploração:** Chamada direta à URL do cron.
- **Impacto:** Execução indevida de tarefas internas.
- **Por que esta severidade:** Média.
- **Limitações:** Resposta 200 pode ser benigna se a tarefa for idempotente.
- **Referências:** [OWASP API Security Top 10 2023 — API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/), [CWE-306](https://cwe.mitre.org/data/definitions/306.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_INTEG_02_cron_sem_segredo`, `test_policies_more_dynamic.py::test_D_OIDC_01_endpoint_de_provedores`

### `S-INTEG-02` — Endpoints internos protegidos por segredo

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Endpoints internos sem verificação de segredo identificada.
- **Como testa:** Confirma verificação de Authorization: Bearer em endpoints internos.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** Verificação detectada.
- **Reprova quando:** Não detectada.
- **Cenário de exploração:** Chamada direta.
- **Impacto:** Tarefas internas acionáveis por terceiros.
- **Por que esta severidade:** Média.
- **Limitações:** Heurística textual.
- **Referências:** [OWASP API Security Top 10 2023 — API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/), [CWE-306](https://cwe.mitre.org/data/definitions/306.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

## API6:2023 — Unrestricted Access to Sensitive Business Flows

Fluxos de negócio sensíveis (compra, transferência, cadastro) sem proteção contra automação/abuso.

### `D-FLOW-01` — Fluxos de negócio sensíveis têm limite anti-automação documentado

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Fluxos sensíveis não documentam limite de uso.
- **Como testa:** Identifica na spec fluxos como transferência, pagamento, cadastro, OTP e reset, e verifica se documentam limite de uso (429).
- **Pré-requisitos:** Spec OpenAPI acessível.
- **Aprova quando:** Os fluxos documentam resposta 429.
- **Reprova quando:** Fluxos sensíveis sem resposta 429 documentada.
- **Cenário de exploração:** Uso de scripts para repetir o fluxo.
- **Impacto:** Automação abusiva de fluxos de negócio.
- **Por que esta severidade:** Média: é uma lacuna de contrato, não exploração comprovada.
- **Limitações:** Avalia a documentação, não o comportamento real. O limite pode existir e não estar documentado.
- **Referências:** [OWASP API Security Top 10 2023 — API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/), [CWE-799](https://cwe.mitre.org/data/definitions/799.html)
- **Testes automatizados:** `test_classification_and_scoring.py::test_indicio_pesa_menos_que_prova`, `test_classification_and_scoring.py::test_nao_executado_nao_altera_score_nem_conta_como_avaliado`, `test_policies_more_dynamic.py::test_D_FLOW_01_fluxos_sensiveis_sem_429_documentado_sao_indicio`, `test_policies_more_dynamic.py::test_D_DISC_01_endpoints_da_spec_fora_do_inventario`

### `D-FLOW-02` — Login protegido contra força bruta

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** indício · **Requer configuração do projeto**
- **Objetivo:** O login não limitou tentativas inválidas repetidas.
- **Como testa:** Faz 12 tentativas de login inválidas com um usuário inexistente e espera bloqueio/limite (429/423/Retry-After). Nenhuma conta real é afetada.
- **Pré-requisitos:** Rota de login configurada.
- **Aprova quando:** O login limita ou bloqueia as tentativas.
- **Reprova quando:** Nenhuma das 12 tentativas foi limitada.
- **Cenário de exploração:** Tentativa automática de senhas.
- **Impacto:** Força bruta e credential stuffing.
- **Por que esta severidade:** Média: indício sem exploração demonstrada.
- **Limitações:** Usuário inexistente pode ser tratado diferente de usuário real; 12 tentativas podem ser poucas.
- **Referências:** [OWASP API Security Top 10 2023 — API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/), [CWE-307](https://cwe.mitre.org/data/definitions/307.html), [CWE-799](https://cwe.mitre.org/data/definitions/799.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_FLOW_02_login_com_e_sem_limite_de_tentativas`, `test_policies_more_dynamic.py::test_D_FLOW_01_fluxos_sensiveis_sem_429_documentado_sao_indicio`

## API7:2023 — Server Side Request Forgery (SSRF)

A API busca uma URL fornecida pelo usuário sem validar, permitindo alcançar recursos internos.

### `D-SSRF-01` — Parâmetros de URL não permitem SSRF

- **Tipo:** teste ao vivo · **Severidade:** CRITICAL · **Prova:** prova direta · **Requer configuração do projeto**
- **Objetivo:** A API faz requisições a endereços informados pelo cliente (SSRF).
- **Como testa:** Envia uma URL-canário hospedada pelo Sentinela em parâmetros GET tipo url/callback/webhook; se o alvo a acessar, a SSRF está confirmada.
- **Pré-requisitos:** Spec com parâmetros de URL; o alvo precisa alcançar o endereço público do Sentinela (PUBLIC_API_URL).
- **Aprova quando:** Nenhum acesso ao canário foi registrado.
- **Reprova quando:** O alvo acessou o canário.
- **Cenário de exploração:** O atacante informa uma URL interna no parâmetro.
- **Impacto:** Acesso a serviços internos, metadados de nuvem e portas não expostas a partir do servidor.
- **Por que esta severidade:** Crítica: permite alcançar a rede interna a partir do servidor.
- **Limitações:** Ausência de acesso NÃO prova que não há SSRF: o alvo pode não alcançar o Sentinela. Só GET e só parâmetros de consulta.
- **Referências:** [OWASP API Security Top 10 2023 — API7:2023](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/), [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
- **Testes automatizados:** `test_classification_and_scoring.py::test_referencias_incluem_owasp_e_cwe`, `test_classification_and_scoring.py::test_chaves_do_conhecimento_existem_no_catalogo`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_D_SSRF_01_detecta_quando_o_alvo_busca_a_url`, `test_policies_vs_lab.py::test_D_SSRF_01_sem_alcance_do_canario_ausencia_nao_descarta`

## API8:2023 — Security Misconfiguration

Cabeçalhos de segurança ausentes, CORS frouxo, TLS fraco, mensagens de erro verbosas, defaults inseguros.

### `D-HEAD-01` — Cabeçalhos de segurança presentes

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** prova direta
- **Objetivo:** Cabeçalhos de segurança HTTP ausentes.
- **Como testa:** Confere HSTS, CSP, X-Content-Type-Options, X-Frame-Options e Referrer-Policy na resposta.
- **Pré-requisitos:** Alvo respondendo.
- **Aprova quando:** Todos os cabeçalhos presentes.
- **Reprova quando:** Um ou mais ausentes (4 ou mais = falha; menos = alerta).
- **Cenário de exploração:** Depende de outra falha (XSS, página embutida) para ser explorado.
- **Impacto:** Reduz a defesa contra clickjacking, MIME sniffing e downgrade para HTTP.
- **Por que esta severidade:** Média: endurecimento; não é exploração direta.
- **Limitações:** Analisa só a resposta da raiz; APIs puras podem dispensar alguns (CSP, X-Frame-Options).
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-693](https://cwe.mitre.org/data/definitions/693.html), [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html)
- **Testes automatizados:** `test_classification_and_scoring.py::test_skip_nunca_vira_aprovado_e_distingue_o_motivo`, `test_policies_more_dynamic.py::test_D_HEAD_01_cabecalhos_ausentes_e_presentes`, `test_policies_more_dynamic.py::test_D_TLS_01_alvo_em_http_e_apontado_com_severidade_baixa`, `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`

### `D-INFO-01` — Servidor não divulga tecnologia/versão

- **Tipo:** teste ao vivo · **Severidade:** LOW · **Prova:** prova direta
- **Objetivo:** O servidor divulga tecnologia e versão.
- **Como testa:** Procura X-Powered-By e versões no header Server.
- **Pré-requisitos:** Alvo respondendo.
- **Aprova quando:** Nenhuma divulgação.
- **Reprova quando:** Cabeçalho com tecnologia/versão.
- **Cenário de exploração:** Reconhecimento prévio do atacante.
- **Impacto:** Facilita a busca por vulnerabilidades conhecidas.
- **Por que esta severidade:** Baixa.
- **Limitações:** Apenas reconhecimento; sem impacto isolado.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-497](https://cwe.mitre.org/data/definitions/497.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_INFO_01_divulgacao_de_tecnologia_e_versao`, `test_policies_more_dynamic.py::test_D_HEAD_01_cabecalhos_ausentes_e_presentes`

### `D-CORS-01` — CORS não permite qualquer origem com credenciais

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta
- **Objetivo:** CORS permite qualquer origem com credenciais.
- **Como testa:** Envia uma origem arbitrária e reprova se ela for refletida junto com Allow-Credentials: true.
- **Pré-requisitos:** Alvo respondendo a requisições com Origin.
- **Aprova quando:** Origem arbitrária não é aceita com credenciais.
- **Reprova quando:** Origem arbitrária aceita com credenciais.
- **Cenário de exploração:** Página do atacante faz fetch com cookies do usuário.
- **Impacto:** Sites de terceiros fazem requisições autenticadas em nome da vítima.
- **Por que esta severidade:** Alta.
- **Limitações:** Testa uma origem na rota raiz; outras rotas podem ter política diferente.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-942](https://cwe.mitre.org/data/definitions/942.html), [CWE-346](https://cwe.mitre.org/data/definitions/346.html)
- **Testes automatizados:** `test_classification_and_scoring.py::test_indicio_pesa_menos_que_prova`, `test_classification_and_scoring.py::test_nao_executado_nao_altera_score_nem_conta_como_avaliado`, `test_policies_more_dynamic.py::test_D_CORS_01_origem_arbitraria_com_credenciais`, `test_policies_more_dynamic.py::test_D_INTEG_01_webhook_sem_assinatura`, `test_policies_vs_lab.py::test_D_CORS_01_sem_cabecalho_cors_e_aprovado_nao_pulado`, `test_policies_vs_lab.py::test_D_SSRF_01_detecta_quando_o_alvo_busca_a_url`

### `D-TLS-01` — Tráfego sobre HTTPS

- **Tipo:** teste ao vivo · **Severidade:** LOW · **Prova:** prova direta
- **Objetivo:** O alvo é acessado por HTTP, sem TLS.
- **Como testa:** Verifica se a URL base usa https://.
- **Pré-requisitos:** Nenhum.
- **Aprova quando:** URL base em HTTPS.
- **Reprova quando:** URL base em HTTP.
- **Cenário de exploração:** Interceptação na rede (MITM).
- **Impacto:** Tráfego legível e alterável na rede.
- **Por que esta severidade:** Baixa em desenvolvimento; alta em produção.
- **Limitações:** Em ambiente local ou de desenvolvimento HTTP é esperado; a avaliação vale para produção.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-319](https://cwe.mitre.org/data/definitions/319.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_TLS_01_alvo_em_http_e_apontado_com_severidade_baixa`, `test_policies_more_dynamic.py::test_D_CORS_01_origem_arbitraria_com_credenciais`

### `S-HEAD-01` — Cabeçalhos de segurança HTTP configurados

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** indício
- **Objetivo:** Cabeçalhos de segurança não configurados no código.
- **Como testa:** Procura a configuração de headers de segurança no código do framework.
- **Pré-requisitos:** Código-fonte do projeto (Next.js).
- **Aprova quando:** Configuração detectada.
- **Reprova quando:** Não detectada.
- **Cenário de exploração:** Ver D-HEAD-01.
- **Impacto:** Ver D-HEAD-01.
- **Por que esta severidade:** Média.
- **Limitações:** Configuração feita no proxy/CDN não aparece no código.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-693](https://cwe.mitre.org/data/definitions/693.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-TLS-01` — mTLS — TLS mútuo por certificado

- **Tipo:** análise de código · **Severidade:** LOW · **Prova:** indício
- **Objetivo:** Sem autenticação mútua por certificado (mTLS) identificada.
- **Como testa:** Procura configuração de autenticação mútua por certificado.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** mTLS detectado.
- **Reprova quando:** Não detectado.
- **Cenário de exploração:** Não se aplica a exploração direta.
- **Impacto:** Clientes não são autenticados por certificado.
- **Por que esta severidade:** Baixa: recomendação.
- **Limitações:** mTLS é requisito de arquitetura, não um defeito universal.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-295](https://cwe.mitre.org/data/definitions/295.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`, `test_static_rules.py::test_regras_nextjs_aprovam_projeto_bem_configurado`, `test_static_rules.py::test_regras_nextjs_apontam_projeto_sem_protecoes`

### `S-SEC-01` — Sem segredos fixos no código

- **Tipo:** análise de código · **Severidade:** CRITICAL · **Prova:** prova direta
- **Objetivo:** Segredos fixos no código.
- **Como testa:** Procura chaves AWS/GitHub/Slack/Google, chaves privadas e atribuições password/secret/token literais (valores mascarados).
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Leitura do código-fonte ou do histórico do Git.
- **Impacto:** Quem acessa o repositório obtém credenciais de produção.
- **Por que esta severidade:** Crítica: exposição direta de credenciais.
- **Limitações:** Pode acusar valores de exemplo ou de teste; arquivos de teste são ignorados.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-259](https://cwe.mitre.org/data/definitions/259.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`, `test_static_rules.py::test_S_SEC_01_nunca_copia_o_segredo_para_a_evidencia`, `test_static_rules.py::test_S_SEC_01_ignora_arquivos_de_teste_e_exemplos`, `test_static_rules.py::test_S_SEC_05_nao_acusa_consulta_parametrizada`, `test_static_rules.py::test_regras_de_nextjs_so_rodam_em_projeto_nextjs`

### `S-SEC-02` — Verificação de certificado TLS não está desligada

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** prova direta
- **Objetivo:** Verificação de certificado TLS desativada no código.
- **Como testa:** Procura verify=False, rejectUnauthorized:false, InsecureSkipVerify e equivalentes.
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Interceptação do tráfego de saída.
- **Impacto:** A aplicação aceita certificados falsos (MITM).
- **Por que esta severidade:** Alta.
- **Limitações:** Pode aparecer em código de desenvolvimento.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-295](https://cwe.mitre.org/data/definitions/295.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`

### `S-SEC-03` — Modo debug não está ativo

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** prova direta
- **Objetivo:** Modo debug ativo no código.
- **Como testa:** Procura debug=True, DEBUG=True, FLASK_DEBUG e devtools no código/configuração.
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Provocar erro e ler a resposta.
- **Impacto:** Stack traces e console interativo expostos.
- **Por que esta severidade:** Média.
- **Limitações:** Pode estar condicionado ao ambiente e não valer em produção.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-489](https://cwe.mitre.org/data/definitions/489.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`

### `S-SEC-05` — Consultas SQL não são montadas por concatenação

- **Tipo:** análise de código · **Severidade:** HIGH · **Prova:** indício
- **Objetivo:** SQL montado por concatenação.
- **Como testa:** Procura SQL construído com f-string, concatenação, format ou template literal em chamadas de banco.
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Entrada maliciosa altera a consulta.
- **Impacto:** Injeção de SQL.
- **Por que esta severidade:** Alta se a entrada for controlável.
- **Limitações:** Não rastreia se o valor concatenado vem de entrada do usuário; pode ser falso positivo.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`, `test_static_rules.py::test_S_SEC_05_nao_acusa_consulta_parametrizada`, `test_static_rules.py::test_sem_pasta_de_codigo_nada_e_aprovado`

### `S-SEC-06` — CORS não libera qualquer origem

- **Tipo:** análise de código · **Severidade:** MEDIUM · **Prova:** prova direta
- **Objetivo:** CORS liberado para qualquer origem no código.
- **Como testa:** Procura configurações de CORS com curinga (*) em várias linguagens.
- **Pré-requisitos:** Pasta do projeto informada.
- **Aprova quando:** Nenhuma ocorrência.
- **Reprova quando:** Ocorrência encontrada.
- **Cenário de exploração:** Ver D-CORS-01.
- **Impacto:** Ver D-CORS-01.
- **Por que esta severidade:** Média.
- **Limitações:** Curinga sem credenciais tem impacto menor.
- **Referências:** [OWASP API Security Top 10 2023 — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/), [CWE-942](https://cwe.mitre.org/data/definitions/942.html)
- **Testes automatizados:** `test_static_rules.py::test_regras_genericas_detectam_o_projeto_inseguro`, `test_static_rules.py::test_regras_genericas_aprovam_o_projeto_seguro`

## API9:2023 — Improper Inventory Management

APIs ou versões esquecidas/não documentadas ainda expostas (shadow e zombie APIs).

### `D-EXPO-01` — Rotas de debug/administração não estão expostas

- **Tipo:** teste ao vivo · **Severidade:** HIGH · **Prova:** prova direta
- **Objetivo:** Rota de debug ou administração acessível sem autenticação.
- **Como testa:** Testa caminhos comuns (/actuator, /.env, /.git/config, /debug, /metrics…) sem credencial.
- **Pré-requisitos:** Alvo respondendo.
- **Aprova quando:** Nenhum dos caminhos testados devolve conteúdo sensível.
- **Reprova quando:** Caminho devolve conteúdo característico (variáveis, config do git, JSON de actuator).
- **Cenário de exploração:** Acesso direto à URL.
- **Impacto:** Vazamento de configuração, segredos e código.
- **Por que esta severidade:** Alta.
- **Limitações:** Lista fixa de 10 caminhos; outros não são testados.
- **Referências:** [OWASP API Security Top 10 2023 — API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/), [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-538](https://cwe.mitre.org/data/definitions/538.html), [CWE-215](https://cwe.mitre.org/data/definitions/215.html)
- **Testes automatizados:** `test_policies_vs_lab.py::test_alvo_vulneravel_e_detectado_com_evidencia`, `test_policies_vs_lab.py::test_D_BOLA_01_confirma_com_controle_de_recurso_inexistente`, `test_policies_vs_lab.py::test_alvo_seguro_nao_gera_vulnerabilidade_alta_ou_critica`, `test_policies_vs_lab.py::test_D_JWT_01_rota_publica_nao_prova_aceitacao_de_token_forjado`

### `D-SOAP-01` — Contrato SOAP (WSDL) não está exposto publicamente

- **Tipo:** teste ao vivo · **Severidade:** MEDIUM · **Prova:** prova direta
- **Objetivo:** Contrato SOAP (WSDL) exposto publicamente.
- **Como testa:** Procura o WSDL em caminhos comuns (?wsdl, /service?wsdl…) e reporta se ele é acessível sem autenticação. Só aparece se houver serviço SOAP.
- **Pré-requisitos:** Serviço SOAP presente.
- **Aprova quando:** WSDL não acessível sem autenticação.
- **Reprova quando:** WSDL acessível.
- **Cenário de exploração:** Leitura do WSDL para planejar ataques.
- **Impacto:** Mapa completo das operações do serviço legado.
- **Por que esta severidade:** Média.
- **Limitações:** Só roda se um WSDL for encontrado.
- **Referências:** [OWASP API Security Top 10 2023 — API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/), [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_SOAP_01_e_D_SOAP_02_wsdl_exposto_e_politica_ws_security`, `test_policies_more_dynamic.py::test_D_BFLA_0N_e_D_BFLA_A1_usuario_admin_nao_e_o_alvo_do_teste`

### `S-DISC-01` — Discovery de endpoints (código)

- **Tipo:** análise de código · **Severidade:** INFO · **Prova:** indício
- **Objetivo:** Inventário de endpoints identificados no código.
- **Como testa:** Lista os endpoints encontrados no código para montar o inventário.
- **Pré-requisitos:** Código-fonte do projeto.
- **Aprova quando:** Rotas identificadas.
- **Reprova quando:** Nenhuma rota identificada gera 'não aplicável'.
- **Cenário de exploração:** Não se aplica.
- **Impacto:** Informativo: endpoints não inventariados são risco de API9.
- **Por que esta severidade:** Informativa.
- **Limitações:** Só Next.js e Express.
- **Referências:** [OWASP API Security Top 10 2023 — API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- **Testes automatizados:** `test_static_rules.py::test_S_DISC_01_lista_rotas_do_codigo_e_aponta_as_fora_do_inventario`, `test_static_rules.py::test_S_DISC_01_sem_rotas_nao_e_aplicavel`

### `D-DISC-01` — Discovery de endpoints (OpenAPI/Swagger)

- **Tipo:** teste ao vivo · **Severidade:** LOW · **Prova:** indício
- **Objetivo:** Endpoints da spec fora do inventário do projeto.
- **Como testa:** Baixa a spec OpenAPI/Swagger exposta e compara com o que está configurado.
- **Pré-requisitos:** Spec acessível.
- **Aprova quando:** Todos os endpoints da spec estão no inventário.
- **Reprova quando:** Endpoints da spec fora do inventário (alerta).
- **Cenário de exploração:** Uso de rotas antigas ou não monitoradas.
- **Impacto:** Endpoints esquecidos (shadow/zombie) fora do radar de segurança.
- **Por que esta severidade:** Baixa.
- **Limitações:** Se a spec não for encontrada, nada é concluído (teste não executado).
- **Referências:** [OWASP API Security Top 10 2023 — API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- **Testes automatizados:** `test_policies_more_dynamic.py::test_D_DISC_01_endpoints_da_spec_fora_do_inventario`, `test_policies_more_dynamic.py::test_D_DISC_01_spec_ausente_e_nao_executado_nao_aprovado`

## API10:2023 — Unsafe Consumption of APIs

Confiar cegamente nos dados de APIs de terceiros consumidas, sem validar.

_Nenhuma política implementada para este item._
