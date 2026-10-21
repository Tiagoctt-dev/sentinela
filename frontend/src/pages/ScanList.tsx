import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, ScanSummary, StatsSummary } from "../api/client";
import Button from "../components/ui/Button";
import ConfirmDialog from "../components/ui/ConfirmDialog";
import EmptyState from "../components/ui/EmptyState";
import { useToast } from "../components/ui/ToastContext";

const scoreClass = (n: number) => (n >= 85 ? "ok" : n >= 60 ? "warn" : "crit");
const verdictClass = (n: number) => (n >= 85 ? "ok" : n >= 60 ? "warn" : "fail");

function timeAgo(iso: string) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const min = Math.round(diffMs / 60000);
  if (min < 1) return "agora";
  if (min < 60) return `há ${min}min`;
  const h = Math.round(min / 60);
  if (h < 24) return `há ${h}h`;
  return `há ${Math.round(h / 24)}d`;
}

export default function ScanListPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [params] = useSearchParams();
  const targetIdFilter = params.get("targetId") || undefined;

  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [stats, setStats] = useState<StatsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<"todos" | "nao_conforme" | "conforme">("todos");
  const [search, setSearch] = useState("");
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = () => {
    setLoading(true);
    api.listScans(targetIdFilter).then(setScans).catch((e) => toast.error(e)).finally(() => setLoading(false));
    api.getStats().then(setStats).catch(() => {});
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [targetIdFilter]);
  async function confirmDelete() {
    if (!deleteId) return;
    setDeleting(true);
    try {
      await api.deleteScan(deleteId);
      setScans((prev) => prev.filter((s) => s.id !== deleteId));
      setDeleteId(null);
    } catch (e) {
      toast.error(e);
    } finally {
      setDeleting(false);
    }
  }

  const filtered = scans.filter((s) => {
    if (filter === "nao_conforme" && s.overall >= 60) return false;
    if (filter === "conforme" && s.overall < 85) return false;
    if (search && !`${s.targetName} ${s.mode}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Scans</h1>
          <div className="eyebrow">
            {targetIdFilter ? (
              <>
                Filtrado por projeto · <Link to="/scans">ver todos</Link>
              </>
            ) : (
              "Passo 2 de 3 — resultados de cada execução, de todos os projetos."
            )}
          </div>
        </div>
        <div className="page-head-actions">
          <input
            type="text"
            placeholder="Buscar projeto"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <Button onClick={() => navigate("/")}>+ Novo scan</Button>
        </div>
      </div>

      {stats && (
        <div className="stat-grid">
          <div className="stat-card">
            <div className="stat-label">Score médio</div>
            <div className="stat-value">{stats.scoreAvg ?? "—"}</div>
            <div className="stat-bar">
              <div style={{ width: `${stats.scoreAvg ?? 0}%` }} />
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Críticos abertos</div>
            <div className={`stat-value ${stats.criticosAbertos > 0 ? "crit" : ""}`}>{stats.criticosAbertos}</div>
            <div className="stat-bar crit">
              <div style={{ width: stats.criticosAbertos > 0 ? "100%" : "0%" }} />
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Endpoints cobertos</div>
            <div className="stat-value">{stats.endpointsCobertos}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Último scan</div>
            <div className="stat-value" style={{ fontSize: 15 }}>
              {stats.lastScan ? timeAgo(stats.lastScan.createdAt) : "—"}
            </div>
          </div>
        </div>
      )}

      <div className="tab-row">
        <button className={filter === "todos" ? "active" : ""} onClick={() => setFilter("todos")}>
          Todos
        </button>
        <button className={filter === "nao_conforme" ? "active" : ""} onClick={() => setFilter("nao_conforme")}>
          Não conforme
        </button>
        <button className={filter === "conforme" ? "active" : ""} onClick={() => setFilter("conforme")}>
          Conforme
        </button>
      </div>

      {loading && <p className="muted">Carregando…</p>}
      {!loading && (
        <div className="scan-table">
          <div className="scan-table-head">
            <span>Score</span>
            <span>Projeto</span>
            <span>Veredito</span>
            <span>Módulos</span>
            <span>Executado</span>
          </div>
          {filtered.map((s) => (
            <div key={s.id} className="scan-row">
              <div className="scan-row-link" onClick={() => navigate(`/scans/${s.id}`)} style={{ display: "contents", cursor: "pointer" }}>
                <div className={`scan-score ${scoreClass(s.overall)}`}>{s.overall}</div>
                <div>
                  <div className="scan-title">{s.targetName}</div>
                  <div className="muted small">{s.origin === "agendado" ? "agendado" : s.createdBy ? `por ${s.createdBy}` : ""}</div>
                  <div className="scan-meta mono">
                    <span className={`pill pill-${verdictClass(s.overall)}`}>{s.verdict}</span>
                    {s.policy && (
                      <span className={`pill ${s.policy.passed ? "pill-ok" : "pill-fail"}`} title={s.policy.reason}>
                        {s.policy.passed ? "política ok" : "política reprovada"}
                      </span>
                    )}
                  </div>
                </div>
                <div className="scan-counts mono">
                  <span className="c-fail">{s.totals.FAIL} falhas</span>
                  <span className="c-warn">{s.totals.WARN} alertas</span>
                  <span className="c-ok">{s.totals.PASS} ok</span>
                </div>
                <div className="scan-mods mono">{s.mode}</div>
              </div>
              <div className="scan-when mono" style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "flex-end" }}>
                {timeAgo(s.createdAt)}
                <button className="ghost danger icon-btn sm" title="Excluir" onClick={() => setDeleteId(s.id)}>
                  🗑
                </button>
              </div>
            </div>
          ))}
          {!filtered.length && (
            <div style={{ padding: "24px 16px" }}>
              {scans.length ? (
                <p className="muted">Nenhum scan bate com o filtro.</p>
              ) : (
                <EmptyState
                  icon="◎"
                  title="Nenhum scan ainda"
                  description='Vá em Projetos e clique em "Rodar scan" — o resultado aparece aqui.'
                  action={<Button onClick={() => navigate("/")}>Ir para Projetos</Button>}
                />
              )}
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={!!deleteId}
        title="Excluir scan"
        description="Excluir este scan do histórico? Essa ação não pode ser desfeita."
        confirmLabel="Excluir"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteId(null)}
      />
    </div>
  );
}
