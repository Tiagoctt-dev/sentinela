import { useEffect, useState } from "react";
import { api, FindingWithContext, TargetInfo } from "../api/client";
import FindingCard from "../components/FindingCard";
import EmptyState from "../components/ui/EmptyState";
import { useToast } from "../components/ui/ToastContext";

export default function FindingsPage() {
  const toast = useToast();
  const [findings, setFindings] = useState<FindingWithContext[]>([]);
  const [targets, setTargets] = useState<TargetInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [resolution, setResolution] = useState("open");
  const [targetId, setTargetId] = useState("");
  const [search, setSearch] = useState("");

  const load = () => {
    setLoading(true);
    api
      .listFindings({
        severity: severity || undefined, resolution: resolution || undefined,
        targetId: targetId || undefined, q: search || undefined,
      })
      .then(setFindings)
      .catch((e) => toast.error(e))
      .finally(() => setLoading(false));
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [severity, resolution, targetId]);
  useEffect(() => {
    const t = setTimeout(load, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);
  useEffect(() => {
    api.listTargets().then(setTargets);
  }, []);

  const projectCount = new Set(findings.map((f) => f.targetId)).size;

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Achados</h1>
          <div className="eyebrow">
            {loading ? "Carregando…" : `${findings.length} achado(s) em ${projectCount} projeto(s) — estado atual, só o scan mais recente de cada um.`}
          </div>
        </div>
        <input type="text" placeholder="Buscar achado" value={search} onChange={(e) => setSearch(e.target.value)} style={{ width: 220 }} />
      </div>

      <div className="run-bar">
        <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
          <option value="">Todos os projetos</option>
          {targets.map((t) => (
            <option key={t.id} value={t.id}>
              {t.config.name || t.name}
            </option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Todas as severidades</option>
          <option value="CRITICAL">Crítico</option>
          <option value="HIGH">Alto</option>
          <option value="MEDIUM">Médio</option>
          <option value="LOW">Baixo</option>
          <option value="INFO">Info</option>
        </select>
        <select value={resolution} onChange={(e) => setResolution(e.target.value)}>
          <option value="">Todos os status</option>
          <option value="open">Aberto</option>
          <option value="resolved">Resolvido</option>
          <option value="risk_accepted">Risco aceito</option>
        </select>
      </div>

      {!loading &&
        findings.map((f) => (
          <FindingCard key={f.rowId} f={f} footer={<p className="muted small">{f.targetName}</p>} />
        ))}
      {!loading && !findings.length && (
        <EmptyState icon="✓" title="Nenhum achado com esses filtros" description="Ajuste os filtros acima ou rode um scan novo." />
      )}
    </div>
  );
}
