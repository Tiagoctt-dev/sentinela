# Catálogo dos controles verificados pelo Sentinela: cada verificação (check)
# com o que testa, como testa e a qual item do OWASP API Security Top 10 (2023)
# pertence. Alimenta a tela de Políticas e o mapeamento OWASP dos achados.

# kind: "static" (lê o código do projeto) | "dynamic" (requisições HTTP ao alvo em execução)
CHECKS = [
    # --- API1 · BOLA
    {"id": "S-BOLA-01", "kind": "static", "severity": "MEDIUM", "owasp": "API1:2023",
     "title": "Autorização em nível de objeto (BOLA)",
     "how": "Lê o schema/rotas e procura modelos com dono (userId) acessados sem filtro pelo dono."},
    {"id": "D-BOLA-01", "kind": "dynamic", "severity": "CRITICAL", "owasp": "API1:2023",
     "title": "BOLA dinâmico — agir sobre o objeto de outro usuário",
     "how": "Cria dois usuários de teste, o usuário B tenta ler/alterar um objeto do usuário A. Reprova se a API deixar."},
    # --- API2 · Autenticação
    {"id": "D-JWT-01", "kind": "dynamic", "severity": "CRITICAL", "owasp": "API2:2023",
     "title": "JWT — alg=none não é aceito",
     "how": "Forja um token com alg=none (sem assinatura) e tenta acessar rota protegida. Reprova se aceitar."},
    {"id": "D-JWT-02", "kind": "dynamic", "severity": "CRITICAL", "owasp": "API2:2023",
     "title": "JWT — segredo HMAC não é trivial",
     "how": "Tenta quebrar a assinatura HS256/384/512 com uma lista de segredos fracos comuns."},
    {"id": "D-JWT-03", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API2:2023",
     "title": "JWT possui claim de expiração (exp)",
     "how": "Decodifica o token recebido no login e verifica se existe o claim exp."},
    {"id": "D-AUTH-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Rota protegida exige token válido",
     "how": "Chama a rota protegida sem token e com token inválido; ambas devem responder 401/403."},
    {"id": "D-AUTHZ-0N", "kind": "dynamic", "severity": "CRITICAL", "owasp": "API2:2023",
     "title": "Acesso não autenticado negado nas rotas configuradas",
     "how": "Acessa cada rota sensível do alvo sem sessão; deve responder 401/403 (nunca 200)."},
    {"id": "S-AUTHZ-02", "kind": "static", "severity": "CRITICAL", "owasp": "API2:2023",
     "title": "Rotas de API verificam autenticação/assinatura",
     "how": "Varre as rotas de API no código e aponta as que não chamam nenhuma verificação de sessão/assinatura."},
    {"id": "S-TOKEN-01", "kind": "static", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Cookies de sessão com flags de proteção",
     "how": "Procura HttpOnly, Secure e SameSite na configuração de cookies de sessão."},
    {"id": "S-TOKEN-02", "kind": "static", "severity": "MEDIUM", "owasp": "API2:2023",
     "title": "Tokens de recuperação expiram e são de uso único",
     "how": "Verifica expiração e remoção do token de reset de senha após o uso."},
    {"id": "S-TOKEN-03", "kind": "static", "severity": "LOW", "owasp": "API2:2023",
     "title": "DPoP — prova de posse do token",
     "how": "Procura vínculo do token a uma chave do cliente (sender-constrained tokens)."},
    {"id": "S-OIDC-01", "kind": "static", "severity": "HIGH", "owasp": "API2:2023",
     "title": "OAuth 2.0 / OpenID Connect configurado",
     "how": "Detecta provedor OAuth/OIDC e persistência de tokens no código."},
    {"id": "S-OIDC-02", "kind": "static", "severity": "MEDIUM", "owasp": "API2:2023",
     "title": "PKCE e state no fluxo de autorização",
     "how": "Confirma PKCE + state no fluxo (ou biblioteca que os aplica por padrão)."},
    {"id": "D-OIDC-01", "kind": "dynamic", "severity": "INFO", "owasp": "API2:2023",
     "title": "Provedores de autenticação disponíveis",
     "how": "Consulta o endpoint de provedores de autenticação do alvo."},
    {"id": "S-INPUT-02", "kind": "static", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Senhas com hash forte (bcrypt)",
     "how": "Procura bcrypt/argon2/scrypt no código de cadastro e login."},
    # --- API3 · Propriedades de objeto
    {"id": "D-EXPOSE-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API3:2023",
     "title": "Resposta não expõe campos sensíveis",
     "how": "Lê a resposta de rota autenticada e procura campos como password, hash, token, secret."},
    {"id": "D-MASS-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API3:2023",
     "title": "Mass assignment — atribuição de campo privilegiado",
     "how": "Envia campos privilegiados (ex.: role=admin) no cadastro e verifica se foram aceitos."},
    {"id": "S-INPUT-01", "kind": "static", "severity": "MEDIUM", "owasp": "API3:2023",
     "title": "Validação de esquema na entrada",
     "how": "Procura validação de esquema (Zod, Pydantic, Joi…) antes de a entrada tocar o banco."},
    # --- API4 · Consumo de recursos
    {"id": "D-RATE-01", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API4:2023",
     "title": "Rate limiting sob rajada de requisições",
     "how": "Dispara 20 requisições em rajada e espera receber 429 (throttling) em alguma delas."},
    # --- API5 · BFLA
    {"id": "D-BFLA-0N", "kind": "dynamic", "severity": "HIGH", "owasp": "API5:2023",
     "title": "BFLA — usuário comum não acessa função administrativa",
     "how": "Loga com um usuário de papel comum e chama as rotas administrativas configuradas; qualquer 2xx reprova."},
    {"id": "S-AUTHZ-01", "kind": "static", "severity": "HIGH", "owasp": "API5:2023",
     "title": "Middleware protege as rotas da aplicação",
     "how": "Confirma que existe middleware global de sessão com matcher cobrindo as rotas."},
    # --- API8 · Misconfiguration
    {"id": "D-HEAD-01", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API8:2023",
     "title": "Cabeçalhos de segurança presentes",
     "how": "Confere HSTS, CSP, X-Content-Type-Options, X-Frame-Options e Referrer-Policy na resposta."},
    {"id": "D-INFO-01", "kind": "dynamic", "severity": "LOW", "owasp": "API8:2023",
     "title": "Servidor não divulga tecnologia/versão",
     "how": "Procura X-Powered-By e versões no header Server."},
    {"id": "D-CORS-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API8:2023",
     "title": "CORS não permite qualquer origem com credenciais",
     "how": "Envia uma origem arbitrária e reprova se ela for refletida junto com Allow-Credentials: true."},
    {"id": "D-TLS-01", "kind": "dynamic", "severity": "LOW", "owasp": "API8:2023",
     "title": "Tráfego sobre HTTPS",
     "how": "Verifica se a URL base usa https://."},
    {"id": "S-HEAD-01", "kind": "static", "severity": "MEDIUM", "owasp": "API8:2023",
     "title": "Cabeçalhos de segurança HTTP configurados",
     "how": "Procura a configuração de headers de segurança no código do framework."},
    {"id": "S-TLS-01", "kind": "static", "severity": "LOW", "owasp": "API8:2023",
     "title": "mTLS — TLS mútuo por certificado",
     "how": "Procura configuração de autenticação mútua por certificado."},
    {"id": "D-INTEG-02", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API8:2023",
     "title": "Endpoint de cron/interno exige segredo",
     "how": "Chama o endpoint de cron configurado sem o segredo Bearer; 401/403 passa, qualquer outro código gera alerta."},
    {"id": "S-INTEG-02", "kind": "static", "severity": "MEDIUM", "owasp": "API8:2023",
     "title": "Endpoints internos protegidos por segredo",
     "how": "Confirma verificação de Authorization: Bearer em endpoints internos."},
    # --- Fase 2: spec OpenAPI, fluxos, SSRF, exposição
    {"id": "D-SPEC-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Rotas protegidas pela spec negam acesso anônimo",
     "how": "Lê a spec OpenAPI e chama, sem credencial, as rotas GET que ela declara protegidas; 2xx reprova. Rotas com nome de ação (create, delete, reset, logout…) nunca são chamadas."},
    {"id": "D-SPEC-02", "kind": "dynamic", "severity": "CRITICAL", "owasp": "API3:2023",
     "title": "Rotas públicas não expõem dados sensíveis",
     "how": "Chama as rotas GET sem 'security' e procura campos como senha, CPF, token na resposta (valores mascarados na evidência)."},
    {"id": "D-FLOW-01", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API6:2023",
     "title": "Fluxos de negócio sensíveis têm limite anti-automação documentado",
     "how": "Identifica na spec fluxos como transferência, pagamento, cadastro, OTP e reset, e verifica se documentam limite de uso (429)."},
    {"id": "D-FLOW-02", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API6:2023",
     "title": "Login protegido contra força bruta",
     "how": "Faz 12 tentativas de login inválidas com um usuário inexistente e espera bloqueio/limite (429/423/Retry-After). Nenhuma conta real é afetada."},
    {"id": "D-SSRF-01", "kind": "dynamic", "severity": "CRITICAL", "owasp": "API7:2023",
     "title": "Parâmetros de URL não permitem SSRF",
     "how": "Envia uma URL-canário hospedada pelo Sentinela em parâmetros GET tipo url/callback/webhook; se o alvo a acessar, a SSRF está confirmada."},
    {"id": "D-EXPO-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API9:2023",
     "title": "Rotas de debug/administração não estão expostas",
     "how": "Testa caminhos comuns (/actuator, /.env, /.git/config, /debug, /metrics…) sem credencial."},
    {"id": "S-SEC-01", "kind": "static", "severity": "CRITICAL", "owasp": "API8:2023",
     "title": "Sem segredos fixos no código",
     "how": "Procura chaves AWS/GitHub/Slack/Google, chaves privadas e atribuições password/secret/token literais (valores mascarados)."},
    {"id": "S-SEC-02", "kind": "static", "severity": "HIGH", "owasp": "API8:2023",
     "title": "Verificação de certificado TLS não está desligada",
     "how": "Procura verify=False, rejectUnauthorized:false, InsecureSkipVerify e equivalentes."},
    {"id": "S-SEC-03", "kind": "static", "severity": "MEDIUM", "owasp": "API8:2023",
     "title": "Modo debug não está ativo",
     "how": "Procura debug=True, DEBUG=True, FLASK_DEBUG e devtools no código/configuração."},
    {"id": "S-SEC-04", "kind": "static", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Hash de senha não usa algoritmo fraco",
     "how": "Procura MD5/SHA-1 aplicados a senhas em várias linguagens."},
    {"id": "S-SEC-05", "kind": "static", "severity": "HIGH", "owasp": "API8:2023",
     "title": "Consultas SQL não são montadas por concatenação",
     "how": "Procura SQL construído com f-string, concatenação, format ou template literal em chamadas de banco."},
    {"id": "S-SEC-06", "kind": "static", "severity": "MEDIUM", "owasp": "API8:2023",
     "title": "CORS não libera qualquer origem",
     "how": "Procura configurações de CORS com curinga (*) em várias linguagens."},
    {"id": "S-SEC-07", "kind": "static", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Tokens JWT são sempre verificados",
     "how": "Procura verificação de assinatura desligada, algoritmo 'none' e expiração ignorada."},
    {"id": "D-SOAP-01", "kind": "dynamic", "severity": "MEDIUM", "owasp": "API9:2023",
     "title": "Contrato SOAP (WSDL) não está exposto publicamente",
     "how": "Procura o WSDL em caminhos comuns (?wsdl, /service?wsdl…) e reporta se ele é acessível sem autenticação. Só aparece se houver serviço SOAP."},
    {"id": "D-SOAP-02", "kind": "dynamic", "severity": "HIGH", "owasp": "API2:2023",
     "title": "Serviço SOAP declara política WS-Security",
     "how": "Verifica no WSDL a presença de política WS-Security (UsernameToken, assinatura/criptografia XML)."},
    # --- API9 · Inventário
    {"id": "S-DISC-01", "kind": "static", "severity": "INFO", "owasp": "API9:2023",
     "title": "Discovery de endpoints (código)",
     "how": "Lista os endpoints encontrados no código para montar o inventário."},
    {"id": "D-DISC-01", "kind": "dynamic", "severity": "LOW", "owasp": "API9:2023",
     "title": "Discovery de endpoints (OpenAPI/Swagger)",
     "how": "Baixa a spec OpenAPI/Swagger exposta e compara com o que está configurado."},
    # --- API10 · Consumo inseguro
    {"id": "S-INTEG-01", "kind": "static", "severity": "HIGH", "owasp": "API10:2023",
     "title": "Webhooks verificam assinatura da requisição",
     "how": "Procura validação de assinatura do provedor antes de processar o webhook."},
    {"id": "D-INTEG-01", "kind": "dynamic", "severity": "HIGH", "owasp": "API10:2023",
     "title": "Webhook rejeita requisição sem assinatura",
     "how": "Envia um POST forjado (formato Twilio/WhatsApp, sem x-twilio-signature) ao webhook configurado; deve responder 403."},
]

from .models import OWASP_API

# Fonte única do mapeamento check → OWASP é OWASP_API (models.py), que o pipeline
# aplica aos achados; aqui só complementamos o que ela não cobre.
for _c in CHECKS:
    _c["owasp"] = OWASP_API.get(_c["id"], _c["owasp"])
    if _c["id"] == "D-AUTHZ-0N":
        _c["owasp"] = OWASP_API["D-AUTHZ-01"]

# Itens do Top 10 que o scanner ainda NÃO testa — mostrados com transparência na UI.
NOT_COVERED_NOTES = {  # itens do Top 10 sem nenhuma verificação
    "API10:2023": "Ainda sem verificação de como a API valida dados vindos de APIs de terceiros que ela consome. A verificação de assinatura de webhooks está listada em Autenticação (API2).",
}

# Verificações dinâmicas que dependem de configuração do projeto (rotas, credenciais de teste,
# campos privilegiados) — sem isso o Sentinela as pula (SKIP) em vez de adivinhar.
NEEDS_CONFIG = {"D-BOLA-01", "D-JWT-01", "D-JWT-02", "D-JWT-03", "D-AUTH-01", "D-AUTHZ-0N",
                "D-EXPOSE-01", "D-MASS-01", "D-INTEG-01", "D-INTEG-02", "D-BFLA-0N",
                "D-SPEC-01", "D-FLOW-02", "D-SSRF-01"}

CHECK_OWASP = {c["id"]: c["owasp"] for c in CHECKS}


def owasp_for_check(check_id: str) -> str | None:
    if check_id in CHECK_OWASP:
        return CHECK_OWASP[check_id]
    if check_id.startswith("D-AUTHZ-"):
        return CHECK_OWASP["D-AUTHZ-0N"]
    if check_id.startswith("D-BFLA-"):
        return CHECK_OWASP["D-BFLA-0N"]
    return None
