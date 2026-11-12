import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, Resolution, Severity, TargetInfo } from "../api/client";
import FindingsTable from "../components/FindingsTable";
import { StackedBar } from "../components/charts/Charts";
import AsyncView from "../components/ui/AsyncView";
import Button from "../components/ui/Button";
import EmptyState from "../components/ui/EmptyState";
import { Field, FormActions } from "../components/ui/Form";
import Modal from "../components/ui/Modal";
import { useToast } from "../components/ui/ToastContext";
import PageHeader from "../components/ui/PageHeader";
import { useAsync } from "../hooks/useAsync";
import { applyFilters, FILTER_KEYS, SORTS, SortKey } from "../lib/findingFilters";
import { CATEGORY_LABEL, RESOLUTION_LABEL, SEVERITIES, SEVERITY_LABEL } from "../lib/results";

const SEV_TONE = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" } as const;
export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const values = useMemo(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""])), [params]);
  const sort = (params.get("ordem") as SortKey) in SORTS ? (params.get("ordem") as SortKey) : "severidade";

  const toast = useToast();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState<Resolution | null>(null);
  const [bulkNote, setBulkNote] = useState("");
  const [bulkDays, setBulkDays] = useState("90");
  const [bulkSaving, setBulkSaving] = useState(false);
  const findings = useAsync(() => api.listFindings(), []);
  const targets = useAsync<TargetInfo[]>(() => api.listTargets(), []);
  const all = useMemo(() => findings.data ?? [], [findings.data]);

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };
  const clear = () => setParams(new URLSearchParams(), { replace: true });

  // contadores vêm do conjunto completo (antes dos filtros de severidade) para servirem de filtro rápido
  const baseForCounters = useMemo(() => applyFilters(all, { ...values, severidade: "" }, "severidade"), [all, values]);
  const counters = SEVERITIES.map((s) => ({ s, n: baseForCounters.filter((f) => f.severity === s).length }));
  const rows = useMemo(() => applyFilters(all, values, sort), [all, values, sort]);
  const filtering = FILTER_KEYS.some((k) => values[k]);
  const advancedActive = ["confianca", "categoria", "politica", "triagem"].some((k) => values[k]);

  // Atalhos j/k: próximo/anterior achado da lista (fora de campos de texto).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "j" && e.key !== "k") return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (e.target as HTMLElement)?.isContentEditable) return;
      const links = Array.from(document.querySelectorAll<HTMLElement>(".table .row-link"));
      if (!links.length) return;
      const at = links.indexOf(document.activeElement as HTMLElement);
      const next = e.key === "j" ? Math.min(at + 1, links.length - 1) : Math.max(at - 1, 0);
      links[at === -1 ? 0 : next].focus();
      e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const visibleSelected = rows.filter((f) => selected.has(f.rowId));
  const toggle = (id: string) => setSelected((cur) => { const n = new Set(cur); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const toggleAll = (checked: boolean) => setSelected(checked ? new Set(rows.map((f) => f.rowId)) : new Set());

  async function applyBulk() {
    if (!bulk) return;
    if (bulk === "risk_accepted" && !bulkNote.trim()) return toast.error("Aceitar o risco exige uma justificativa.");
    setBulkSaving(true);
    let ok = 0;
    const failed: string[] = [];
    for (const f of visibleSelected) {
      try {
        await api.updateFinding(f.rowId, {
          resolution: bulk,
          resolutionNote: bulkNote.trim() || undefined,
          ...(bulk === "risk_accepted" && bulkDays ? { expiresInDays: Number(bulkDays) } : {}),
        });
        ok++;
      } catch {
        failed.push(f.title);
      }
    }
    setBulkSaving(false);
    setBulk(null);
    setBulkNote("");
    setSelected(new Set());
    findings.reload();
    if (failed.length) toast.error(`${ok} atualizado(s); ${failed.length} falharam: ${failed.slice(0, 2).join("; ")}${failed.length > 2 ? "…" : ""}`);
    else toast.success(`${ok} achado(s) atualizado(s).`);
  }

  const categories = [...new Set(all.map((f) => f.category))].sort();
  const policies = [...new Set(all.map((f) => f.id))].sort();

  return (
    <div>
      <PageHeader
        title="Achados de segurança"
        description="Vulnerabilidades confirmadas e prováveis no último scan de cada projeto. Para ver o que foi testado em cada rota, abra Rotas e verificações."
        actions={<Link className="btn ghost" to="/rotas">Rotas e verificações</Link>}
      />

      <AsyncView loading={findings.loading} error={findings.error} onRetry={findings.reload} hasData={!!findings.data}>
        {all.length === 0 ? (
          <EmptyState icon="✓" title="Nenhum achado de segurança" description="Os scans mais recentes não encontraram vulnerabilidades confirmadas ou prováveis — ou ainda não há scans. Verifique a cobertura em Rotas e verificações." action={<Link className="btn" to="/projetos">Rodar um scan</Link>} />
        ) : (
          <>
            <section className="panel" aria-label="Resumo das vulnerabilidades">
              <div className="sev-counters">
                {counters.map(({ s, n }) => (
                  <button
                    key={s}
                    className={`sev-counter tone-border-${SEV_TONE[s]} ${values.severidade === s ? "active" : ""}`}
                    onClick={() => set("severidade", values.severidade === s ? "" : s)}
                    aria-pressed={values.severidade === s}
                  >
                    <span className="n">{n}</span>
                    <span>{SEVERITY_LABEL[s as Severity]}</span>
                  </button>
                ))}
              </div>
              <StackedBar
                label="Achados por severidade"
                segments={counters.map(({ s, n }) => ({ key: s, label: SEVERITY_LABEL[s], value: n, tone: SEV_TONE[s] }))}
              />
            </section>

            <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filtros">
              <input type="search" placeholder="Buscar por achado, política, rota ou projeto" value={values.q} onChange={(e) => set("q", e.target.value)} aria-label="Buscar" className="filter-search" />
              <select value={values.projeto} onChange={(e) => set("projeto", e.target.value)} aria-label="Projeto">
                <option value="">Todos os projetos</option>
                {(targets.data ?? []).map((t) => (
                  <option key={t.id} value={t.id}>{t.config.name || t.name}</option>
                ))}
              </select>
              <select value={values.estado} onChange={(e) => set("estado", e.target.value)} aria-label="Estado">
                <option value="">Qualquer estado</option>
                <option value="vulnerable">Confirmada</option>
                <option value="likely">Provável</option>
              </select>
              <details className="filters-more" open={advancedActive}>
                <summary>Mais filtros{advancedActive ? " (ativos)" : ""}</summary>
                <div className="filters-more-body">
              <select value={values.confianca} onChange={(e) => set("confianca", e.target.value)} aria-label="Confiança">
                <option value="">Qualquer confiança</option>
                <option value="confirmed">Confirmada</option>
                <option value="indicative">Indício</option>
              </select>
              <select value={values.categoria} onChange={(e) => set("categoria", e.target.value)} aria-label="Categoria">
                <option value="">Todas as categorias</option>
                {categories.map((c) => (
                  <option key={c} value={c}>{CATEGORY_LABEL[c] ?? c}</option>
                ))}
              </select>
              <select value={values.politica} onChange={(e) => set("politica", e.target.value)} aria-label="Política">
                <option value="">Todas as políticas</option>
                {policies.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
              <select value={values.triagem} onChange={(e) => set("triagem", e.target.value)} aria-label="Estado de validação">
                <option value="">Qualquer triagem</option>
                {Object.entries(RESOLUTION_LABEL).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
                </div>
              </details>
              {filtering && <Button variant="ghost" type="button" onClick={clear}>Limpar filtros</Button>}
            </form>

            <p className="result-count" role="status" aria-live="polite">
              Mostrando <b>{rows.length}</b> de <b>{all.length}</b> achado(s){filtering ? " com os filtros aplicados" : ""}. <span className="muted">Atalhos: <kbd>j</kbd>/<kbd>k</kbd> para percorrer a lista.</span>
            </p>

            {visibleSelected.length > 0 && (
              <div className="bulk-bar" role="region" aria-label="Ações em lote">
                <b>{visibleSelected.length} selecionado(s)</b>
                <Button size="sm" onClick={() => setBulk("resolved")}>Marcar como resolvido</Button>
                <Button size="sm" variant="ghost" onClick={() => setBulk("risk_accepted")}>Aceitar risco</Button>
                <Button size="sm" variant="ghost" onClick={() => setBulk("open")}>Reabrir</Button>
                <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Limpar seleção</Button>
              </div>
            )}

            {rows.length === 0 ? (
              <EmptyState icon="⌕" title="Nenhum achado com esses filtros" description="Ajuste ou limpe os filtros para ver os demais." action={<Button onClick={clear}>Limpar filtros</Button>} />
            ) : (
              <div className="table-wrap">
                <FindingsTable findings={rows} showProject sort={sort} onSort={(k) => set("ordem", k)} selected={selected} onToggle={toggle} onToggleAll={toggleAll} />
              </div>
            )}
          </>
        )}
      </AsyncView>

      <Modal open={!!bulk} onClose={() => setBulk(null)} title={bulk === "resolved" ? `Marcar ${visibleSelected.length} como resolvido` : bulk === "risk_accepted" ? `Aceitar o risco de ${visibleSelected.length} achado(s)` : `Reabrir ${visibleSelected.length} achado(s)`}>
        <p className="desc">A mesma nota{bulk === "risk_accepted" ? " e validade valem" : " vale"} para todos os achados selecionados. Cada um fica registrado individualmente na auditoria.</p>
        <Field label="Nota" optional={bulk !== "risk_accepted"} hint={bulk === "risk_accepted" ? "Obrigatória: explique por que o risco é aceitável." : "Ex.: link do chamado ou do commit."}>
          <textarea rows={3} value={bulkNote} onChange={(e) => setBulkNote(e.target.value)} />
        </Field>
        {bulk === "risk_accepted" && (
          <Field label="Validade do aceite" hint="Depois do prazo o achado reabre sozinho.">
            <select value={bulkDays} onChange={(e) => setBulkDays(e.target.value)}>
              <option value="30">30 dias</option>
              <option value="90">90 dias</option>
              <option value="180">180 dias</option>
              <option value="365">1 ano</option>
              <option value="">Sem prazo</option>
            </select>
          </Field>
        )}
        <FormActions>
          <Button variant="ghost" onClick={() => setBulk(null)} disabled={bulkSaving}>Cancelar</Button>
          <Button onClick={applyBulk} loading={bulkSaving} loadingLabel="Aplicando…">Aplicar a {visibleSelected.length}</Button>
        </FormActions>
      </Modal>
    </div>
  );
}

