# Limitações conhecidas

O que o Sentinela **não** garante. Estas limitações também aparecem na tela de Políticas e, por scan, em "Escopo e cobertura".

## Cobertura de segurança

- **Nenhum item do OWASP API Top 10 está "totalmente coberto".** Hoje: API8 com cobertura ampla; API1–API7 e API9 parciais; **API10 sem verificação**. Os limites de cada item estão em [politicas.md](politicas.md).
- **BOLA:** testa **uma** rota informada no projeto, com dois usuários de teste. Rotas `/recurso/{id}` descobertas pela spec não são testadas automaticamente. A confirmação usa o código HTTP (e um controle com recurso inexistente); não confere se o dado realmente mudou.
- **BFLA automático:** só rotas `GET` com `admin`/`internal`/`debug` no nome ou na tag.
- **SSRF:** só parâmetros de **consulta** com nome de URL; o alvo precisa alcançar o Sentinela (`PUBLIC_API_URL`). Sem isso o resultado é "inconclusivo".
- **Rate limiting:** uma rajada de 20 requisições é **indício**, não prova.
- **Fluxos de negócio (API6):** avalia a documentação de limites e o brute force no login; não simula abuso de regra de negócio.
- **Injeção (SQLi/XSS/XXE) e fuzzing não são testados dinamicamente.**
- **Autenticação suportada:** login por JSON simples com o token no corpo da resposta. Não cobre MFA/OTP, OAuth por redirecionamento, SSO nem sessão só por cookie.
- **Spec OpenAPI:** sem spec, a descoberta de rotas fica limitada às rotas configuradas.
- **Análise de código:** heurística por texto (sem análise de fluxo de dados). Regras de Next.js/Prisma só rodam em projetos Next.js; as genéricas têm padrões para várias linguagens, mas foram exercitadas só em Python/JS. Pode haver falsos positivos e negativos.
- **Recomendações de endurecimento** (DPoP, mTLS) e itens de inventário aparecem como "provável" de baixa severidade, embora sejam boas práticas e não vulnerabilidades.

## Segurança do Sentinela

- **Sem isolamento por organização:** todo usuário logado lê todos os projetos e scans (os papéis limitam a escrita e o acesso às áreas sensíveis).
- **Sem SSO/AD** (OIDC/SAML): o login é próprio (scrypt + token HMAC de 8 h; sair, trocar ou redefinir a senha **revogam** o token; guardado em `localStorage`, não em cookie `HttpOnly`).
- **Proteção contra SSRF** valida o destino no cadastro e antes do scan; um DNS malicioso poderia mudar a resposta entre a validação e a requisição (DNS rebinding).
- **Retenção:** a trilha de auditoria é expurgada após 365 dias por padrão e os scans só são expurgados se `SENTINELA_SCAN_RETENTION_DAYS` for definido (o scan mais recente de cada projeto nunca é apagado). A evidência mascara senhas, tokens, CPF, cartão, JWT e e-mail, mas o mascaramento é por padrão de texto.
- Testes que **escrevem no alvo** exigem autorização explícita no projeto, mas, uma vez autorizados, podem alterar ou excluir registros de teste. Use homologação.
- O bloqueio de tentativas de login é por e-mail+IP; atrás de proxy reverso o IP visto é o do proxy (configure o cabeçalho de IP real na borda).

## Operação

- Scans rodam **dentro da requisição** (limite de 300 s e 3 simultâneos por padrão: `SENTINELA_SCAN_TIMEOUT_S`, `SENTINELA_MAX_CONCURRENT_SCANS`); não há fila persistente.
- O agendador roda no mesmo processo do servidor e só executa com ele ligado; vários processos não duplicam a execução (reivindicação atômica no banco).
- Sem Alembic: colunas novas entram por `ADD COLUMN IF NOT EXISTS` no start (ver [arquitetura.md](arquitetura.md)).
- O PDF é a impressão do navegador (sem geração no servidor).
- `docs/arquitetura-doc.html` é um documento anterior à refatoração e **não foi revisado**; a referência atual é `docs/arquitetura.md`.
- `frontend/src/components/SeverityBar.tsx` não é usado por nenhuma tela (arquivo preexistente, não removido por não ser de autoria desta refatoração).

## Débitos técnicos

- `Targets.tsx` e `Integrations.tsx` ainda concentram bastante lógica de formulário (dívida de tamanho, não de correção).
- O backend ainda usa sessões síncronas do SQLAlchemy dentro de rotas `async` (bloqueia o laço de eventos sob carga alta).
- As três integrações repetem o CRUD em `routes_integrations.py`.
- Sem testes de navegador automatizados (ver [testes.md](testes.md)).
