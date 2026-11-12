import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, ScanSummary } from "../api/client";
import AsyncView from "../components/ui/AsyncView";
import Button from "../components/ui/Button";
import ConfirmDialog from "../components/ui/ConfirmDialog";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import StatTile from "../components/ui/StatTile";
import { useToast } from "../components/ui/ToastContext";
import { useAsync } from "../hooks/useAsync";
import { formatDate, timeAgo } from "../lib/results";

const VERDICTS = ["Todos", "Não conforme", "Parcialmente conforme", "Conforme"] as const;
const verdictTone = (v: string) => (v === "Conforme" ? "ok" : v === "Parcialmente conforme" ? "warn" : "fail");

export default function ScanListPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [params] = useSearchParams();
  const targetId = params.get("targetId") || undefined;

  const scans = useAsync<ScanSummary[]>(() => api.listScans(targetId), [targetId]);
  const stats = useAsync(() => api.getStats(), [scans.data?.length]);
  const [verdict, setVerdict] = useState<(typeof VERDICTS)[number]>("Todos");
  const [search, setSearch] = useState("");
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const rows = useMemo(
    () =>
      (scans.data ?? []).filter(
        (s) => (verdict === "Todos" || s.verdict === verdict) && (!search || `${s.targetName} ${s.mode}`.toLowerCase().includes(search.toLowerCase())),
      ),
    [scans.data, verdict, search],
  );

  async function confirmDelete() {
    if (!deleteId) return;
    setDeleting(true);
    try {
      await api.deleteScan(deleteId);
      scans.setData((prev) => (prev ?? []).filter((s) => s.id !== deleteId));
      setDeleteId(null);
      toast.success("Scan excluído.");
    } catch (e) {
      toast.error(e);
    } finally {
      setDeleting(false);
    }
  }

  const s = stats.data;

  return (
    <div>
      <PageHeader
        title="Scans"
        crumbs={targetId ? [{ label: "Scans", to: "/scans" }, { label: "Filtrado por projeto" }] : undefined}
        description={targetId ? <>Histórico de um projeto · <Link to="/scans">ver todos</Link></> : "Histórico de execuções de todos os projetos."}
        actions={
          <>
            <input type="search" placeholder="Buscar projeto" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Buscar projeto" className="filter-search narrow" />
            <Button onClick={() => navigate("/projetos")}>Novo scan</Button>
          </>
        }
      />

      {s && (
        <div className="stat-row">
          <StatTile label="Scans" value={s.totalScans} />
          <StatTile label="Projetos" value={s.totalProjects} />
          <StatTile label="Críticas confirmadas em aberto" value={s.criticosAbertos} tone={s.criticosAbertos ? "crit" : undefined} hint="Último scan de cada projeto" />
          <StatTile label="Último scan" value={s.lastScan ? timeAgo(s.lastScan.createdAt) : "—"} hint={s.lastScan?.targetName} />
        </div>
      )}

      <div className="tab-row" role="group" aria-label="Filtrar por veredito">
        {VERDICTS.map((v) => (
          <button key={v} className={verdict === v ? "active" : ""} onClick={() => setVerdict(v)} aria-pressed={verdict === v}>
            {v}
          </button>
        ))}
      </div>

      <AsyncView loading={scans.loading} error={scans.error} onRetry={scans.reload} hasData={!!scans.data}>
        {rows.length === 0 ? (
          scans.data?.length ? (
            <EmptyState icon="⌕" title="Nenhum scan com esse filtro" description="Troque o projeto ou a origem selecionada para ver os demais scans." />
          ) : (
            <EmptyState icon="◎" title="Nenhum scan ainda" description='Vá em Projetos e clique em "Rodar scan" — o resultado aparece aqui.' action={<Button onClick={() => navigate("/projetos")}>Ir para Projetos</Button>} />
          )
        ) : (
          <div className="table-wrap">
            <table className="table stack-on-mobile">
              <caption className="sr-only">Histórico de scans</caption>
              <thead>
                <tr>
                  <th scope="col">Projeto</th>
                  <th scope="col">Resultado</th>
                  <th scope="col">Achados</th>
                  <th scope="col">Cobertura</th>
                  <th scope="col">Executado</th>
                  <th scope="col"><span className="sr-only">Ações</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const st = r.totals.states;
                  return (
                    <tr key={r.id}>
                      <td data-label="Projeto" className="cell-main">
                        <Link to={`/scans/${r.id}`} className="row-link">{r.targetName}</Link>
                        <div className="cell-sub">{r.origin === "agendado" ? "agendado" : r.createdBy ? `por ${r.createdBy}` : r.mode}</div>
                      </td>
                      <td data-label="Resultado">
                        <b className="score">{r.overall}</b> <span className={`pill pill-${verdictTone(r.verdict)}`}>{r.verdict}</span>
                        {r.policy && <div className="cell-sub">{r.policy.passed ? "política aprovada" : "política reprovada"}</div>}
                      </td>
                      <td data-label="Achados">
                        {st ? (
                          <>
                            <b>{st.vulnerable}</b> confirmadas · <b>{st.likely}</b> prováveis
                            <div className="cell-sub">{st.passed} aprovadas · {st.not_run + st.inconclusive + st.error} sem conclusão</div>
                          </>
                        ) : (
                          <span className="muted">{r.totals.FAIL} falhas · {r.totals.WARN} alertas</span>
                        )}
                      </td>
                      <td data-label="Cobertura">
                        {r.scope ? (
                          <>
                            <b>{r.scope.coveragePct}%</b>
                            <div className="cell-sub">{r.scope.mode === "authenticated" ? "autenticado" : "externo"}</div>
                          </>
                        ) : (
                          <span className="muted" title="Scan anterior ao registro de escopo">—</span>
                        )}
                      </td>
                      <td data-label="Executado" title={formatDate(r.createdAt)} className="mono">{timeAgo(r.createdAt)}</td>
                      <td className="cell-action">
                        <Button variant="ghost" size="sm" className="danger" onClick={() => setDeleteId(r.id)} aria-label={`Excluir scan de ${r.targetName}`}>
                          Excluir
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </AsyncView>

      <ConfirmDialog
        open={!!deleteId}
        title="Excluir scan"
        description="Excluir este scan do histórico, com todos os seus achados? Essa ação não pode ser desfeita."
        confirmLabel="Excluir"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteId(null)}
      />
    </div>
  );
}
