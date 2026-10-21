# OWASP API Security Top 10 (2023) — base de conhecimento do Sentinela

O scanner é ancorado no **OWASP API Security Top 10 (2023)**. Cada achado é
marcado com a categoria correspondente (`API1:2023` … `API10:2023`), e esta
mesma taxonomia é injetada como contexto na camada de IA generativa, para que
as recomendações fiquem embasadas na fonte oficial.

> Referência: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>

## As 10 categorias e a cobertura atual

| # | Categoria | O que é | Como o Sentinela cobre |
|---|-----------|---------|------------------------|
| **API1:2023** | Broken Object Level Authorization (BOLA) | Acessar objeto de outro usuário manipulando o id | ✅ Análise estática de posse: mapeia toda operação por id e verifica escopo por `userId` (`S-BOLA-01`) |
| **API2:2023** | Broken Authentication | Falhas em login/tokens/sessão | ✅ Auth em rotas, cookies protegidos, OAuth/OIDC/PKCE, expiração de token; dinâmico: 401 sem sessão |
| **API3:2023** | Broken Object Property Level Authorization | Exposição/alteração de propriedades indevidas | ⚠️ Parcial: validação de schema (Zod) na entrada; verificação de campos sensíveis no roadmap |
| **API4:2023** | Unrestricted Resource Consumption | Sem rate limiting / quotas | ⚠️ Sinaliza endpoints públicos sem proteção contra abuso |
| **API5:2023** | Broken Function Level Authorization (BFLA) | Acessar função sem o papel correto | ✅ Verifica se rotas/funções exigem sessão ou prova de origem |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | Fluxos sensíveis sem proteção contra automação | 🔜 Roadmap |
| **API7:2023** | Server Side Request Forgery (SSRF) | API busca URL do usuário sem validar | 🔜 Roadmap |
| **API8:2023** | Security Misconfiguration | Headers ausentes, CORS/TLS fracos, erros verbosos | ✅ Cabeçalhos de segurança (estático + dinâmico), X-Powered-By, HTTPS |
| **API9:2023** | Improper Inventory Management | APIs/versões esquecidas expostas | ⚠️ Parcial: inventário de endpoints do alvo |
| **API10:2023** | Unsafe Consumption of APIs | Confiar cegamente em API de terceiro | 🔜 Roadmap |

Legenda: ✅ coberto · ⚠️ parcial · 🔜 planejado.

## Notas sobre o teste de BOLA (API1)

BOLA é a vulnerabilidade **nº 1** em APIs e a mais comum na prática. O Sentinela
faz uma análise estática de autorização em nível de objeto:

1. Identifica os "modelos do usuário" (os que têm `userId` no schema).
2. Mapeia toda operação por id (`update/delete/findUnique/findFirst/...`).
3. Verifica se cada uma restringe por `userId` — inline (`where: { id, userId }`)
   ou por uma checagem de dono imediatamente anterior.
4. Marca para revisão as que estabelecem a posse de forma indireta (via
   chamador, loop sobre coleção escopada, ou job de sistema).

> Próximo passo: teste **dinâmico** de BOLA (dois usuários autenticados
> tentando acessar o objeto um do outro).
