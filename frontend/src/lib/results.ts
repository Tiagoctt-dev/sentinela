// Vocabulário único dos resultados: como cada estado, confiança e severidade é nomeado e ordenado na UI.
// A interface só traduz o que o backend devolve — nunca converte um estado desconhecido em "aprovado".

import type { Confidence, FindingState, RouteState, Severity } from "../api/client";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Crítica", HIGH: "Alta", MEDIUM: "Média", LOW: "Baixa", INFO: "Informativa",
};

export const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export const STATES: FindingState[] = ["vulnerable", "likely", "inconclusive", "error", "passed", "not_run", "not_applicable"];

export interface StateMeta {
  label: string;
  short: string;
  icon: string;
  tone: "crit" | "high" | "warn" | "ok" | "na";
  help: string;
}

export const STATE_META: Record<FindingState, StateMeta> = {
  vulnerable: { label: "Vulnerabilidade confirmada", short: "Confirmada", icon: "✘", tone: "crit", help: "A condição da falha foi observada e comprovada." },
  likely: { label: "Vulnerabilidade provável", short: "Provável", icon: "▲", tone: "high", help: "Há indício parcial; exige validação manual." },
  inconclusive: { label: "Inconclusivo", short: "Inconclusivo", icon: "?", tone: "warn", help: "O teste executou, mas a evidência não permite concluir." },
  error: { label: "Erro de execução", short: "Erro", icon: "!", tone: "warn", help: "O teste não pôde ser concluído por falha de rede, timeout ou resposta inválida." },
  passed: { label: "Aprovado no escopo verificado", short: "Aprovado", icon: "✔", tone: "ok", help: "Nenhuma falha encontrada dentro do que foi efetivamente testado." },
  not_run: { label: "Não executado", short: "Não executado", icon: "–", tone: "na", help: "Aplicável, mas faltou um pré-requisito (credencial, configuração ou autorização)." },
  not_applicable: { label: "Não aplicável", short: "Não aplicável", icon: "∅", tone: "na", help: "O alvo não possui a superfície testada." },
};

export const ROUTE_STATE_META: Record<RouteState, StateMeta> = {
  vulnerable: STATE_META.vulnerable,
  likely: STATE_META.likely,
  error: STATE_META.error,
  inconclusive: STATE_META.inconclusive,
  passed: { ...STATE_META.passed, label: "Sem falha nas verificações executadas", short: "Sem falha" },
  not_run: STATE_META.not_run,
  not_tested: { label: "Descoberta, sem teste", short: "Não testada", icon: "○", tone: "na", help: "A rota foi descoberta, mas nenhuma verificação a alcançou." },
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: "Confirmada", indicative: "Indício", none: "—",
};

export const RESOLUTION_LABEL: Record<string, string> = {
  open: "Aberto", resolved: "Resolvido", risk_accepted: "Risco aceito",
};

export const CATEGORY_LABEL: Record<string, string> = {
  AUTHORIZATION: "Autorização", TOKEN_SESSION: "Token e sessão", OAUTH_OIDC: "OAuth / OIDC",
  TRANSPORT: "Transporte", HEADERS: "Cabeçalhos e exposição", INPUT_VALIDATION: "Validação de entrada",
  INTEGRITY: "Integridade", INVENTORY: "Inventário",
};

/** Estado desconhecido (ex.: backend mais novo que a UI) aparece como tal — nunca como aprovado. */
export function stateMeta(state: string | null | undefined): StateMeta {
  return STATE_META[state as FindingState] ?? { label: `Estado desconhecido (${state ?? "ausente"})`, short: "Desconhecido", icon: "?", tone: "warn", help: "Estado não reconhecido por esta versão da interface." };
}

export const isProblem = (state: string | null | undefined): boolean => state === "vulnerable" || state === "likely";

export function compareFindings(a: { severity: Severity; state: FindingState }, b: { severity: Severity; state: FindingState }): number {
  const stateRank = (s: FindingState) => (s === "vulnerable" ? 0 : s === "likely" ? 1 : 2);
  return stateRank(a.state) - stateRank(b.state) || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
}

export function countBy<T, K extends string>(items: T[], key: (item: T) => K): Partial<Record<K, number>> {
  const out: Partial<Record<K, number>> = {};
  for (const item of items) {
    const k = key(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

export function assetLabel(asset: { method?: string; path?: string; param?: string } | null | undefined): string {
  if (!asset?.path) return "Alvo (raiz)";
  return `${asset.method ?? "GET"} ${asset.path}${asset.param ? ` · ${asset.param}` : ""}`;
}

export function formatDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString("pt-BR") : "—";
}

export function timeAgo(iso: string, now: number = Date.now()): string {
  const min = Math.round((now - new Date(iso).getTime()) / 60000);
  if (min < 1) return "agora";
  if (min < 60) return `há ${min} min`;
  const h = Math.round(min / 60);
  if (h < 24) return `há ${h} h`;
  return `há ${Math.round(h / 24)} d`;
}
