import { Link, useSearchParams } from "react-router-dom";
import { api, ScanSummary, TargetInfo } from "../api/client";
import RoutesPanel from "../components/RoutesPanel";
import AsyncView from "../components/ui/AsyncView";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import { useAsync } from "../hooks/useAsync";
import { formatDate } from "../lib/results";

/** Rotas e verificações do scan mais recente de um projeto (ou de um scan específico, via ?scan=). */
export default function RoutesPage() {
  const [params, setParams] = useSearchParams();
  const targets = useAsync<TargetInfo[]>(() => api.listTargets(), []);
  const scans = useAsync<ScanSummary[]>(() => api.listScans(), []);

  const targetId = params.get("projeto") ?? "";
  const list = scans.data ?? [];
  const latestPerTarget = new Map<string, ScanSummary>();
  for (const s of list) if (!latestPerTarget.has(s.targetId)) latestPerTarget.set(s.targetId, s); // lista vem do mais novo ao mais antigo

  const projects = (targets.data ?? []).filter((t) => latestPerTarget.has(t.id));
  const chosenId = targetId && latestPerTarget.has(targetId) ? targetId : projects[0]?.id ?? "";
  const scan = chosenId ? latestPerTarget.get(chosenId) : undefined;

  return (
    <div>
      <PageHeader
        title="Rotas e verificações"
        description="Quais rotas foram descobertas e testadas, e qual foi o resultado de cada verificação. Para ver os problemas encontrados, abra Achados de segurança."
        actions={<Link className="btn ghost" to="/achados">Achados de segurança</Link>}
      />

      <AsyncView loading={scans.loading || targets.loading} error={scans.error || targets.error} onRetry={() => { scans.reload(); targets.reload(); }} hasData={!!scans.data && !!targets.data}>
        {!scan ? (
          <EmptyState icon="∅" title="Ainda não há scans" description="Rode um scan para ver as rotas descobertas e o resultado de cada verificação." action={<Link className="btn" to="/projetos">Ir para Projetos</Link>} />
        ) : (
          <>
            <div className="context-bar">
              <label>
                Projeto
                <select value={chosenId} onChange={(e) => setParams({ projeto: e.target.value }, { replace: true })}>
                  {projects.map((t) => (
                    <option key={t.id} value={t.id}>{t.config.name || t.name}</option>
                  ))}
                </select>
              </label>
              <span className="muted">
                Último scan: {formatDate(scan.createdAt)} · <Link to={`/scans/${scan.id}`}>abrir scan</Link>
              </span>
            </div>
            <RoutesPanel scanId={scan.id} />
          </>
        )}
      </AsyncView>
    </div>
  );
}
