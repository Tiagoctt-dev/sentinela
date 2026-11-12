import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ScanComparison, ScanDetail as ScanDetailT } from "../api/client";
import CategoryBars from "../components/CategoryBars";
import FindingsTable from "../components/FindingsTable";
import Gauge from "../components/Gauge";
import RoutesPanel from "../components/RoutesPanel";
import { CoverageMeter } from "../components/charts/Charts";
import { useScanRun } from "../components/ScanRunContext";
import AsyncView from "../components/ui/AsyncView";
import { SevBadge, StateBadge } from "../components/ui/Badge";
import Button from "../components/ui/Button";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import ProgressIndicator, { useElapsed } from "../components/ui/ProgressIndicator";
import TabLinks from "../components/ui/TabLinks";
import { useToast } from "../components/ui/ToastContext";
import { useAsync } from "../hooks/useAsync";
import { compareFindings, formatDate, isProblem, STATE_META, STATES } from "../lib/results";

type Tab = "resumo" | "achados" | "rotas";

export default function ScanDetailPage({ tab }: { tab: Tab }) {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const { run, active } = useScanRun();
  const query = useAsync<ScanDetailT>(() => api.getScan(id), [id]);
  const scan = query.data;
  const [rerunning, setRerunning] = useState(false);
  const elapsed = useElapsed(rerunning);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [comparing, setComparing] = useState(false);

  const problems = useMemo(() => (scan ? scan.findings.filter((f) => isProblem(f.state)).sort(compareFindings) : []), [scan]);

  async function rerun() {
    if (!scan) return;
    setRerunning(true);
    try {
      const fresh = await run(scan.targetName, () => api.runScan({ targetId: scan.targetId }));
      navigate(`/scans/${fresh.id}`);
    } catch {
      // erro já exibido pelo ScanRunContext
    } finally {
      setRerunning(false);
    }
  }

  async function compare() {
    if (!scan) return;
    setComparing(true);
    try {
      setComparison(await api.compareScan(scan.id));
    } catch (e) {
      toast.error(e);
    } finally {
      setComparing(false);
    }
  }

  async function exportSarif() {
    if (!scan) return;
    try {
      const text = await api.scanSarif(scan.id);
      const url = URL.createObjectURL(new Blob([text], { type: "application/sarif+json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinela-${scan.id.slice(0, 8)}.sarif`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      toast.error(e);
    }
  }

  const states = scan?.totals.states;
  const scope = scan?.scope ?? null;
  const base = `/scans/${id}`;

  return (
    <div>
      <PageHeader
        title={scan?.targetName ?? "Scan"}
        crumbs={[{ label: "Scans", to: "/scans" }, { label: scan?.targetName ?? "Detalhe" }]}
        description={
          scan && (
            <span className="mono">
              {formatDate(scan.createdAt)} · {scan.mode}
              {scan.origin === "agendado" ? " · agendado" : scan.createdBy ? ` · por ${scan.createdBy}` : ""}
            </span>
          )
        }
        actions={
          scan && (
            <>
              <Button variant="ghost" onClick={compare} loading={comparing} loadingLabel="Comparando…">Comparar com anterior</Button>
              <Button variant="ghost" onClick={exportSarif} title="Formato SARIF 2.1.0, aceito por GitHub Code Scanning, Azure DevOps e SonarQube">Exportar SARIF</Button>
              <Button variant="ghost" onClick={() => window.print()} title="Abre a impressão — escolha “Salvar como PDF”">Exportar PDF</Button>
              {rerunning ? <ProgressIndicator elapsedMs={elapsed} /> : <Button onClick={rerun} disabled={!!active}>Rodar novamente</Button>}
            </>
          )
        }
      />

      <AsyncView loading={query.loading} error={query.error} onRetry={query.reload} hasData={!!scan}>
        {scan && (
          <>
            <TabLinks
              label="Seções do scan"
              items={[
                { to: base, label: "Resumo", end: true },
                { to: `${base}/achados`, label: "Achados de segurança", count: problems.length },
                { to: `${base}/rotas`, label: "Rotas e verificações", count: scope ? scope.checksExecuted : null },
              ]}
            />

            {comparison && (
              <section className="panel compare-panel" aria-label="Comparação com a execução anterior">
                {!comparison.previous ? (
                  <p className="muted">Este é o primeiro scan do projeto — não há execução anterior para comparar.</p>
                ) : (
                  <>
                    <div className="compare-head">
                      <b>Comparação com o scan de {formatDate(comparison.previous.createdAt)}</b>
                      <span className={`pill ${(comparison.delta ?? 0) > 0 ? "pill-ok" : (comparison.delta ?? 0) < 0 ? "pill-fail" : "pill-na"}`}>
                        score {comparison.previous.overall} → {scan.overall} ({(comparison.delta ?? 0) > 0 ? "+" : ""}{comparison.delta})
                      </span>
                      <button className="ghost sm no-print" onClick={() => setComparison(null)}>Fechar</button>
                    </div>
                    <div className="compare-cols">
                      <div>
                        <div className="compare-title">Novos problemas ({comparison.new?.length ?? 0})</div>
                        {comparison.new?.map((f) => <Link key={f.rowId} to={`/achados/${f.rowId}`}>{f.title}</Link>)}
                        {!comparison.new?.length && <span className="muted small">Nenhum.</span>}
                      </div>
                      <div>
                        <div className="compare-title">Corrigidos ({comparison.fixed?.length ?? 0})</div>
                        {comparison.fixed?.map((f) => <span key={f.rowId}>{f.title}</span>)}
                        {!comparison.fixed?.length && <span className="muted small">Nenhum.</span>}
                      </div>
                      <div>
                        <div className="compare-title">Persistem ({comparison.persisting ?? 0}) · Pioraram ({comparison.worse?.length ?? 0})</div>
                        {comparison.worse?.map((f) => <Link key={f.rowId} to={`/achados/${f.rowId}`}>{f.title}</Link>)}
                      </div>
                    </div>
                    {!!comparison.notComparable?.length && (
                      <p className="muted small compare-note">
                        {comparison.notComparable.length} verificação(ões) com problema antes não puderam ser reavaliadas agora (por exemplo, sem credenciais) e <b>não</b> contam como corrigidas.
                      </p>
                    )}
                  </>
                )}
              </section>
            )}

            {tab === "resumo" && (
              <>
                <div className="summary-grid">
                  <section className="panel score-panel" aria-label="Resultado do scan">
                    <Gauge score={scan.overall} verdict={scan.verdict} />
                    <p className="muted small score-note">
                      Índice de conformidade nas verificações <b>executadas</b>. Não é uma garantia de segurança — leia junto com a cobertura.
                    </p>
                    {scan.policy && (
                      <div className={`policy-banner ${scan.policy.passed ? "pass" : "fail"}`}>
                        {scan.policy.passed ? "✔ Aprovado" : "✘ Reprovado"} pela política “{scan.policy.policyName}” — {scan.policy.reason}
                        {!!scan.policy.pending?.length && (
                          <div className="small">Pendente de validação manual (indício crítico): {scan.policy.pending.join(", ")}</div>
                        )}
                      </div>
                    )}
                  </section>

                  <section className="panel" aria-label="Escopo e cobertura">
                    <h2>Escopo e cobertura</h2>
                    {scope ? (
                      <>
                        <p className="scope-mode">
                          <span className={`pill ${scope.mode === "authenticated" ? "pill-ok" : "pill-na"}`}>
                            {scope.mode === "authenticated" ? "Scan autenticado" : "Scan externo"}
                          </span>{" "}
                          {scope.credentials.count > 0 ? `${scope.credentials.count} usuário(s) de teste (${scope.credentials.roles.join(", ")})` : "sem usuários de teste"}
                        </p>
                        <CoverageMeter pct={scope.coveragePct} executed={scope.checksExecuted} planned={scope.checksPlanned} />
                        {scope.limitations.length > 0 && (
                          <>
                            <h3 className="small-title">Limitações deste scan</h3>
                            <ul className="limit-list">
                              {scope.limitations.map((l) => <li key={l}>{l}</li>)}
                            </ul>
                          </>
                        )}
                        {scope.notRun.length > 0 && (
                          <p className="small">
                            <Link to={`${base}/rotas`}>Ver as {scope.notRun.length} verificações não executadas →</Link>
                          </p>
                        )}
                      </>
                    ) : (
                      <p className="muted">Este scan é anterior ao registro de escopo, então não há como informar a cobertura. Rode um novo scan.</p>
                    )}
                  </section>
                </div>

                <section className="panel" aria-label="Verificações por estado">
                  <h2>Verificações por estado</h2>
                  {states ? (
                    <div className="chips">
                      {STATES.map((s) => (
                        <span key={s} className={`chip tone-${STATE_META[s].tone}`} title={STATE_META[s].help}>
                          <span aria-hidden="true">{STATE_META[s].icon}</span> {STATE_META[s].label} <b>{states[s] ?? 0}</b>
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">Totais por estado indisponíveis para este scan.</p>
                  )}
                </section>

                <section className="panel" aria-label="Categorias">
                  <h2>Categorias</h2>
                  <CategoryBars categories={scan.categories} />
                </section>

                {scan.ai.length > 0 && (
                  <div className="ai-grid">
                    {scan.ai.map((o) => (
                      <section key={o.key} className={`ai-panel ${o.enabled ? "" : "disabled"}`}>
                        <div className="ai-head">
                          {o.provider}
                          {o.model && <span className="ai-meta mono">{o.model}</span>}
                        </div>
                        {o.enabled && o.summary ? <p>{o.summary}</p> : <p className="muted">{o.reason}</p>}
                      </section>
                    ))}
                  </div>
                )}

                {problems.length > 0 && (
                  <section className="panel" aria-label="Principais achados">
                    <h2>Principais achados</h2>
                    <ul className="top-findings">
                      {problems.slice(0, 5).map((f) => (
                        <li key={f.rowId}>
                          <SevBadge severity={f.severity} /> <StateBadge state={f.state} short />{" "}
                          <Link to={`/achados/${f.rowId}`}>{f.title}</Link>
                        </li>
                      ))}
                    </ul>
                    {problems.length > 5 && <p><Link to={`${base}/achados`}>Ver todos os {problems.length} achados →</Link></p>}
                  </section>
                )}
              </>
            )}

            {tab === "achados" &&
              (problems.length === 0 ? (
                <EmptyState icon="✓" title="Nenhuma vulnerabilidade confirmada ou provável neste scan" description="Isso vale somente para as verificações executadas — confira a cobertura em Rotas e verificações." action={<Link className="btn ghost" to={`${base}/rotas`}>Ver verificações</Link>} />
              ) : (
                <div className="table-wrap">
                  <FindingsTable findings={problems} />
                </div>
              ))}

            {tab === "rotas" && <RoutesPanel scanId={scan.id} />}
          </>
        )}
      </AsyncView>
    </div>
  );
}
