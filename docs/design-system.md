# Design system do Sentinela

Catálogo vivo em **/design** (rota da própria interface): mostra os componentes reais com os tokens reais, nos temas claro e escuro.

## Princípios

1. **Cor nunca é o único canal.** Severidade, estado e confiança sempre têm texto (e ícone, quando cabe).
2. **Sem números inventados.** A interface exibe o que o backend devolve; não recalcula estado, severidade nem cobertura.
3. **Tema claro por padrão; o escuro segue o sistema** (`prefers-color-scheme`).
4. **Acessibilidade é requisito, não polimento:** contraste AA, foco visível, teclado completo, alvos de toque de 44 px em telas de toque, respeito a `prefers-reduced-motion`.

## Tokens (`frontend/src/styles.css`)

| Grupo | Tokens |
|---|---|
| Superfícies | `--bg`, `--bg-raised`, `--panel`, `--panel-2`, `--panel-3`, `--border`, `--border-strong` |
| Texto | `--ink`, `--ink-2`, `--muted`, `--faint` |
| Acento | `--accent`, `--accent-strong`, `--accent-soft`, `--on-accent` |
| Estado | `--ok`/`--ok-soft` |
| Severidade | `--crit`, `--high`, `--med`, `--low`, `--na` (+ `-soft` de cada) e `--on-crit` |
| Campos | `--field-border` (≥ 3:1 sobre o fundo do campo, WCAG 1.4.11) |
| Espaço | `--sp-1` (4 px) … `--sp-9` (56 px) |
| Tipografia | `--fs-xs` (12 px, **piso**) … `--fs-3xl`; `--font-sans` (Inter), `--font-mono` (JetBrains Mono) |
| Raios / sombras | `--radius-sm|md|lg`, `--shadow-sm|md|lg` |

Regra: **não use hexadecimal em componentes.** Use o token. A única exceção é a folha de impressão (PDF), que fixa cores para papel.

### Contraste (testado)
`src/test/contrast.test.ts` lê os tokens do CSS e falha se qualquer par ficar abaixo do mínimo: texto ≥ 4,5:1 sobre cada superfície, etiqueta de severidade sobre o próprio fundo suave ≥ 4,5:1, borda de campo ≥ 3:1 — nos dois temas.

## Componentes (`frontend/src/components/ui`)

| Componente | Quando usar |
|---|---|
| `Button` (`primary`, `ghost`, `danger`; `md`, `sm`; `loading`) | Ações. Rótulo começa com verbo ("Rodar scan", não "OK"). |
| `Field` / `FormGrid` / `FormSection` / `FormActions` | Todo formulário. `hint` explica o campo; `optional` marca o que pode ficar vazio. |
| `Modal` | Diálogos. Foco entra, Tab fica preso dentro, Esc fecha, foco volta a quem abriu. |
| `ConfirmDialog` | Ações destrutivas: descreva a consequência e nomeie o botão pela ação. |
| `SevBadge`, `StateBadge`, `ConfidenceBadge`, `StatusPill` | Severidade, estado do teste, confiança, status simples. |
| `StatTile`, gráficos (`StackedBar`, `BarList`, `Donut`, `TrendChart`, `CoverageMeter`) | Números reais; gráfico de tendência tem tabela alternativa. |
| `EmptyState` | O que é + por que está vazio + como começar. |
| `AsyncView` | Carregando / erro com "tentar de novo" / conteúdo. |
| `MoreMenu`, `TabLinks`, `PageHeader` | Navegação e cabeçalho de página. |

## Estados que todo controle interativo deve ter
padrão · hover · foco (`:focus-visible`) · desabilitado · carregando (quando assíncrono) · erro (quando validável).

## Texto (pt-BR)
- Erros dizem **o que aconteceu, por quê e o que fazer** (ver `friendlyMessage` em `api/client.ts`).
- "Aprovado" significa *nenhuma falha encontrada no que foi testado* — nunca "seguro".
- Estados de resultado: Confirmada, Provável, Inconclusivo, Erro, Aprovado, Não executado, Não se aplica.

## Glossário (use sempre estes termos)

| Termo | Significa | Não usar |
|---|---|---|
| Achado | Vulnerabilidade confirmada ou provável | "issue", "finding" |
| Verificação | Um teste que o Sentinela executa (política) | "check", "regra" |
| Confirmada | A condição da falha foi observada e comprovada | "crítica" (isso é severidade) |
| Provável | Há indício; exige validação manual | "possível" |
| Aprovado | Nenhuma falha no que foi testado | "seguro", "ok" |
| Não executado | Faltou login, spec ou autorização | "pulado" |
| Triagem | Aberto, resolvido ou risco aceito (com validade) | "status" |
| Projeto | Sistema cadastrado para escanear | "alvo" na interface |

## Produto e interação (decisões)
- **Busca global:** Ctrl/⌘ + K abre páginas, projetos, scans e achados. Teclado completo.
- **Tema:** Automático (segue o sistema), Claro ou Escuro, no rodapé do menu; guardado no navegador.
- **Achados:** título curto + frase explicativa; seleção múltipla para triagem em lote; j/k percorre a lista.
- **Detalhe do achado:** resumo → onde → evidência → como corrigir → histórico; contexto recolhido.
- **Visão geral:** primeiros passos (some ao concluir), "Comece por aqui" (3 achados mais graves) e cartões que levam à lista filtrada.
- **Scan em andamento:** banner com a etapa atual (ex.: "etapa 3 de 6"), consultando `GET /api/scans/progress`.
- **Cores de gráfico** (`--chart-*`) são separadas das cores de texto (`--crit` etc.): foram validadas para daltonismo e contraste de 3:1; os segmentos têm 2 px de separação e sempre há rótulo numérico.
- **Escala tipográfica:** 12 / 13 / 14 / 16 / 20 / 24 / 28 / 32. **Raios:** 6 / 10 / 14 / pílula.
