import { Link } from "react-router-dom";
import type { Finding, FindingWithContext } from "../api/client";
import type { SortKey } from "../lib/findingFilters";
import { assetLabel, CATEGORY_LABEL, RESOLUTION_LABEL } from "../lib/results";
import { SevBadge, StateBadge } from "./ui/Badge";

type Row = Finding & Partial<Pick<FindingWithContext, "targetName" | "scanId">>;

interface Props {
  findings: Row[];
  showProject?: boolean;
  sort?: SortKey;
  onSort?: (key: SortKey) => void;
  /** Seleção para triagem em lote (opcional). */
  selected?: Set<string>;
  onToggle?: (rowId: string) => void;
  onToggleAll?: (checked: boolean) => void;
}

/** Lista de achados. Título curto em destaque; a frase explicativa vem logo abaixo. Nada é recalculado aqui. */
export default function FindingsTable({ findings, showProject = false, sort, onSort, selected, onToggle, onToggleAll }: Props) {
  const selectable = !!selected && !!onToggle;
  const allChecked = selectable && findings.length > 0 && findings.every((f) => selected!.has(f.rowId));
  const someChecked = selectable && !allChecked && findings.some((f) => selected!.has(f.rowId));

  // Cabeçalho ordenável: botão dentro do <th>, com aria-sort para leitores de tela.
  const th = (label: string, key?: SortKey) =>
    key && onSort ? (
      <th scope="col" aria-sort={sort === key ? "ascending" : "none"}>
        <button type="button" className={`th-sort ${sort === key ? "active" : ""}`} onClick={() => onSort(key)} title={`Ordenar por ${label.toLowerCase()}`}>
          {label}
          {sort === key && <span aria-hidden="true"> ↓</span>}
        </button>
      </th>
    ) : (
      <th scope="col">{label}</th>
    );

  return (
    <table className="table stack-on-mobile">
      <caption className="sr-only">Achados de segurança</caption>
      <thead>
        <tr>
          {selectable && (
            <th scope="col" className="cell-check">
              <input
                type="checkbox"
                aria-label="Selecionar todos os achados da lista"
                checked={allChecked}
                ref={(el) => { if (el) el.indeterminate = someChecked; }}
                onChange={(e) => onToggleAll?.(e.target.checked)}
              />
            </th>
          )}
          {th("Severidade", "severidade")}
          {th("Achado")}
          {th("Ativo afetado", "ativo")}
          {th("Situação", "confianca")}
          {th("Triagem")}
          {showProject && th("Projeto", "projeto")}
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => {
          const isSel = selectable && selected!.has(f.rowId);
          return (
            <tr key={f.rowId} className={isSel ? "row-selected" : undefined}>
              {selectable && (
                <td className="cell-check" data-label="Selecionar">
                  <input type="checkbox" aria-label={`Selecionar: ${f.title}`} checked={isSel} onChange={() => onToggle!(f.rowId)} />
                </td>
              )}
              <td data-label="Severidade">
                <SevBadge severity={f.severity} />
              </td>
              <td data-label="Achado" className="cell-main">
                <Link to={`/achados/${f.rowId}`} className="row-link">
                  {f.title}
                </Link>
                {f.meta?.headline && f.meta.headline !== f.title && <div className="cell-summary">{f.meta.headline}</div>}
                <div className="cell-sub">
                  <span className="mono">{f.id}</span> · {CATEGORY_LABEL[f.category] ?? f.category}
                  {f.owasp && <> · <span className="owasp">{f.owasp}</span></>}
                </div>
              </td>
              <td data-label="Ativo afetado" className="mono cell-asset">
                {assetLabel(f.asset)}
                {f.asset?.httpStatus != null && <span className="cell-sub"> HTTP {f.asset.httpStatus}</span>}
              </td>
              <td data-label="Situação">
                <StateBadge state={f.state} short />
              </td>
              <td data-label="Triagem">
                <span className={`res-badge res-${f.resolution}`}>{RESOLUTION_LABEL[f.resolution] ?? f.resolution}</span>
              </td>
              {showProject && (
                <td data-label="Projeto">
                  {f.scanId ? <Link to={`/scans/${f.scanId}`}>{f.targetName}</Link> : f.targetName}
                </td>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
