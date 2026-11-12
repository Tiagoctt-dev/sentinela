import type { FindingWithContext } from "../api/client";
import { assetLabel, compareFindings } from "./results";

export const SORTS = {
  severidade: "Severidade",
  confianca: "Confiança",
  ativo: "Ativo afetado",
  projeto: "Projeto",
} as const;
export type SortKey = keyof typeof SORTS;

export const FILTER_KEYS = ["q", "projeto", "severidade", "confianca", "estado", "categoria", "politica", "triagem"] as const;

/** Filtra e ordena no cliente. Nunca altera os campos de um achado — só decide quais aparecem e em que ordem. */
export function applyFilters(rows: FindingWithContext[], p: Record<string, string>, sort: SortKey): FindingWithContext[] {
  const q = (p.q ?? "").trim().toLowerCase();
  const out = rows.filter((f) => {
    if (p.projeto && f.targetId !== p.projeto) return false;
    if (p.severidade && f.severity !== p.severidade) return false;
    if (p.confianca && f.confidence !== p.confianca) return false;
    if (p.estado && f.state !== p.estado) return false;
    if (p.categoria && f.category !== p.categoria) return false;
    if (p.politica && f.id !== p.politica) return false;
    if (p.triagem && f.resolution !== p.triagem) return false;
    if (q) {
      const hay = `${f.meta?.headline ?? ""} ${f.title} ${f.id} ${assetLabel(f.asset)} ${f.targetName} ${f.detail ?? ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const cmp: Record<SortKey, (a: FindingWithContext, b: FindingWithContext) => number> = {
    severidade: compareFindings,
    confianca: (a, b) => (a.confidence === b.confidence ? compareFindings(a, b) : a.confidence === "confirmed" ? -1 : 1),
    ativo: (a, b) => assetLabel(a.asset).localeCompare(assetLabel(b.asset)),
    projeto: (a, b) => a.targetName.localeCompare(b.targetName) || compareFindings(a, b),
  };
  return [...out].sort(cmp[sort]);
}
