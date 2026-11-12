import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, RouteItem, RouteState } from "../api/client";
import { useAsync } from "../hooks/useAsync";
import { filterRoutes } from "../lib/routeFilters";
import { ROUTE_STATE_META, STATE_META } from "../lib/results";
import AsyncView from "./ui/AsyncView";
import { RouteStateBadge, SevBadge, StateBadge } from "./ui/Badge";
import EmptyState from "./ui/EmptyState";
import StatTile from "./ui/StatTile";

const ROUTE_STATES: RouteState[] = ["vulnerable", "likely", "error", "inconclusive", "not_tested", "not_run", "passed"];

/** Rotas e verificações de um scan: o estado da rota e o estado de cada verificação aparecem separados. */
export default function RoutesPanel({ scanId }: { scanId: string }) {
  const view = useAsync(() => api.scanRoutes(scanId), [scanId]);
  const [state, setState] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const data = view.data;

  const rows = useMemo(() => (data ? filterRoutes(data.routes, state, q) : []), [data, state, q]);
  const key = (r: RouteItem) => `${r.method} ${r.path}`;
  const toggle = (k: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  return (
    <AsyncView loading={view.loading} error={view.error} onRetry={view.reload} hasData={!!data}>
      {data && (
        <>
          <div className="stat-row">
            <StatTile label="Rotas" value={data.counts.routes} hint="Conhecidas ou com verificação" />
            <StatTile label="Conhecidas" value={data.counts.known} hint="Pela spec, código ou configuração" />
            <StatTile label="Testadas" value={data.counts.tested} hint="Das conhecidas" />
            <StatTile label="Pendentes" value={data.counts.pending} hint="Conhecidas, sem teste" tone={data.counts.pending ? "warn" : undefined} />
            <StatTile label="Verificações não executadas" value={data.pendingChecks.length} hint="Faltou pré-requisito" tone={data.pendingChecks.length ? "warn" : undefined} />
          </div>

          <div className="chips" aria-label="Verificações por estado">
            {(Object.keys(STATE_META) as (keyof typeof STATE_META)[]).map((s) => (
              <span key={s} className={`chip tone-${STATE_META[s].tone}`}>
                <span aria-hidden="true">{STATE_META[s].icon}</span> {STATE_META[s].short} <b>{data.counts.checks[s] ?? 0}</b>
              </span>
            ))}
          </div>

          <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filtros de rotas">
            <input type="search" className="filter-search" placeholder="Buscar rota, método ou política" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Buscar" />
            <select value={state} onChange={(e) => setState(e.target.value)} aria-label="Estado da rota">
              <option value="">Todos os estados</option>
              {ROUTE_STATES.map((s) => (
                <option key={s} value={s}>
                  {ROUTE_STATE_META[s].short} ({data.counts.byState[s] ?? 0})
                </option>
              ))}
            </select>
          </form>

          <p className="result-count" role="status">
            Mostrando <b>{rows.length}</b> de <b>{data.routes.length}</b> rota(s). O estado da rota é o pior resultado entre as verificações que a alcançaram; “sem falha” não significa que a rota seja segura.
          </p>

          {data.routes.length === 0 ? (
            <EmptyState icon="∅" title="Nenhuma rota registrada neste scan" description="Informe a spec OpenAPI, as rotas protegidas ou o código do projeto para que o Sentinela descubra e teste rotas." />
          ) : rows.length === 0 ? (
            <EmptyState icon="⌕" title="Nenhuma rota com esses filtros" description="Limpe os filtros para ver todas as rotas deste scan." />
          ) : (
            <div className="table-wrap">
              <table className="table stack-on-mobile routes-table">
                <caption className="sr-only">Rotas e resultado de cada verificação</caption>
                <thead>
                  <tr>
                    <th scope="col">Método</th>
                    <th scope="col">Rota</th>
                    <th scope="col">Estado da rota</th>
                    <th scope="col">Verificações</th>
                    <th scope="col">Origem</th>
                    <th scope="col"><span className="sr-only">Detalhes</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const k = key(r);
                    const expanded = open.has(k);
                    return (
                      <Fragment key={k}>
                        <tr>
                          <td data-label="Método" className="mono">{r.method}</td>
                          <td data-label="Rota" className="mono cell-main">{r.label ? `${r.path} (${r.label})` : r.path}</td>
                          <td data-label="Estado da rota"><RouteStateBadge state={r.state} /></td>
                          <td data-label="Verificações">{r.checks.length ? `${r.checks.length} executada(s)` : "nenhuma"}</td>
                          <td data-label="Origem" className="muted">{r.sources.join(", ") || "—"}</td>
                          <td className="cell-action">
                            {r.checks.length > 0 && (
                              <button className="ghost sm" onClick={() => toggle(k)} aria-expanded={expanded} aria-controls={`det-${k}`}>
                                {expanded ? "Ocultar" : "Detalhar"}
                              </button>
                            )}
                          </td>
                        </tr>
                        {expanded && (
                          <tr className="detail-row" id={`det-${k}`}>
                            <td colSpan={6}>
                              <table className="table inner">
                                <thead>
                                  <tr>
                                    <th scope="col">Política</th>
                                    <th scope="col">Severidade</th>
                                    <th scope="col">Resultado</th>
                                    <th scope="col">HTTP</th>
                                    <th scope="col">Observação</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {r.checks.map((c, i) => (
                                    <tr key={`${c.checkId}-${i}`}>
                                      <td>
                                        {c.findingRowId ? <Link to={`/achados/${c.findingRowId}`}>{c.title}</Link> : c.title}
                                        <div className="cell-sub mono">{c.checkId}</div>
                                      </td>
                                      <td><SevBadge severity={c.severity} /></td>
                                      <td><StateBadge state={c.state} short /></td>
                                      <td className="mono">{c.httpStatus ?? "—"}</td>
                                      <td className="muted">{c.note ?? "—"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <section className="panel" aria-labelledby="h-pend">
            <h2 id="h-pend">Verificações não executadas ({data.pendingChecks.length})</h2>
            <p className="panel-sub">Aplicáveis a este projeto, mas sem pré-requisito. Contam como cobertura pendente — nunca como aprovadas.</p>
            {data.pendingChecks.length === 0 ? (
              <p className="muted">Todas as verificações aplicáveis foram executadas.</p>
            ) : (
              <ul className="pending-list">
                {data.pendingChecks.map((c) => (
                  <li key={c.id}>
                    <b>{c.title}</b> <span className="mono muted">{c.id}</span>
                    <div className="muted">{c.reason}</div>
                  </li>
                ))}
              </ul>
            )}
            {data.notApplicableChecks.length > 0 && (
              <details className="definitions">
                <summary>Não aplicáveis a este projeto ({data.notApplicableChecks.length})</summary>
                <ul className="pending-list">
                  {data.notApplicableChecks.map((c) => (
                    <li key={c.id}>
                      <b>{c.title}</b> <span className="mono muted">{c.id}</span>
                      <div className="muted">{c.reason}</div>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </section>
        </>
      )}
    </AsyncView>
  );
}
