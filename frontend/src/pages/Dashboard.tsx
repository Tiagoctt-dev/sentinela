import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, TargetInfo } from "../api/client";
import { BarList, Donut, Segment, StackedBar, TrendChart } from "../components/charts/Charts";
import AsyncView from "../components/ui/AsyncView";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import StatTile from "../components/ui/StatTile";
import { useAsync } from "../hooks/useAsync";
import { assetLabel, CATEGORY_LABEL, compareFindings, SEVERITIES, SEVERITY_LABEL, STATE_META, STATES, formatDate } from "../lib/results";
import { SevBadge, StateBadge } from "../components/ui/Badge";

const SEV_TONE = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" } as const;
const STATE_TONE = { vulnerable: "crit", likely: "high", inconclusive: "warn", error: "warn", passed: "ok", not_run: "na", not_applicable: "na" } as const;

export default function DashboardPage() {
  const [targetId, setTargetId] = useState("");
  const targets = useAsync<TargetInfo[]>(() => api.listTargets(), []);
  const dash = useAsync(() => api.getDashboard(targetId || undefined), [targetId]);
  const d = dash.data;
  const scans = useAsync(() => api.listScans(), []);
  const list = useAsync(() => api.listFindings(targetId ? { targetId } : {}), [targetId]);
  const priorities = useMemo(() => [...(list.data ?? [])].filter((f) => f.resolution === "open").sort(compareFindings).slice(0, 3), [list.data]);
  const steps = useMemo(() => {
    const mine = (targets.data ?? []).filter((t) => t.source === "custom").length > 0;
    return [
      { label: "Cadastrar um projeto", done: mine || (d?.projects ?? 0) > 0, to: "/projetos", cta: "Novo projeto" },
      { label: "Rodar o primeiro scan", done: (d?.projects ?? 0) > 0, to: "/projetos", cta: "Rodar scan" },
      { label: "Rodar um scan autenticado (usuários de teste)", done: (scans.data ?? []).some((s) => s.scope?.mode === "authenticated"), to: "/projetos", cta: "Cadastrar usuários" },
      { label: "Triar o primeiro achado", done: (list.data ?? []).some((f) => f.resolution !== "open"), to: "/achados", cta: "Abrir achados" },
    ];
  }, [targets.data, d, list.data, scans.data]);
  const allDone = steps.every((s) => s.done);

  const severity: Segment[] = d
    ? SEVERITIES.map((s) => ({ key: s, label: SEVERITY_LABEL[s], value: d.findings.bySeverity[s] ?? 0, tone: SEV_TONE[s] }))
    : [];
  const states: Segment[] = d
    ? STATES.map((s) => ({ key: s, label: STATE_META[s].short, value: d.findings.byState[s] ?? 0, tone: STATE_TONE[s] }))
    : [];
  const totalChecks = states.reduce((n, s) => n + s.value, 0);
  const problems = d ? d.findings.byState.vulnerable + d.findings.byState.likely : 0;
  // Aviso de leitura: o painel não pode passar a impressão de "tudo certo" quando a cobertura é baixa ou o scan é antigo.
  const latest = d?.trend.length ? new Date(d.trend[d.trend.length - 1].createdAt) : null;
  const staleDays = latest ? Math.floor((Date.now() - latest.getTime()) / 86_400_000) : 0;
  const lowCoverage = d?.coverage.avgPct != null && d.coverage.avgPct < 60;

  return (
    <div>
      <PageHeader
        title="Visão geral"
        description="Resumo do último scan de cada projeto. Os números vêm dos resultados salvos — nada é estimado."
        actions={
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)} aria-label="Filtrar por projeto" className="select-inline">
            <option value="">Todos os projetos</option>
            {(targets.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.config.name || t.name}
              </option>
            ))}
          </select>
        }
      />

      <AsyncView loading={dash.loading} error={dash.error} onRetry={dash.reload} hasData={!!d}>
        {d && d.projects === 0 && (
          <EmptyState
            icon="◎"
            title="Ainda não há resultados"
            description={d.missing[0] ?? "Rode um scan para gerar os indicadores."}
            action={<Link className="btn" to="/projetos">Ir para Projetos</Link>}
          />
        )}

        {d && d.projects > 0 && (
          <>
            {!allDone && (
              <section className="panel getting-started" aria-labelledby="h-start">
                <h2 id="h-start">Primeiros passos</h2>
                <p className="panel-sub">{steps.filter((s) => s.done).length} de {steps.length} concluídos.</p>
                <ol className="steps">
                  {steps.map((s) => (
                    <li key={s.label} className={s.done ? "done" : ""}>
                      <span className="step-mark" aria-hidden="true">{s.done ? "✓" : ""}</span>
                      <span className="step-label">{s.label}{s.done && <span className="sr-only"> (concluído)</span>}</span>
                      {!s.done && <Link className="btn ghost sm" to={s.to}>{s.cta}</Link>}
                    </li>
                  ))}
                </ol>
              </section>
            )}

            {(lowCoverage || staleDays >= 14) && (
              <div className="notice warn" role="note">
                <b>Leia os números com cautela.</b>{" "}
                {lowCoverage && <>A cobertura média é de {d.coverage.avgPct}%: parte das verificações não rodou (falta login, spec ou autorização), então “sem achados” não significa “sem falhas”. </>}
                {staleDays >= 14 && <>O scan mais recente tem {staleDays} dias; rode um novo para refletir o estado atual. </>}
                <Link to="/rotas">Ver o que ficou sem teste</Link>
              </div>
            )}

            <div className="stat-row">
              <StatTile label="Projetos analisados" value={d.projects} to="/projetos" />
              <StatTile label="Vulnerabilidades confirmadas" value={d.findings.byState.vulnerable} tone={d.findings.byState.vulnerable ? "crit" : undefined} hint="Com prova direta" to="/achados?estado=vulnerable" />
              <StatTile label="Vulnerabilidades prováveis" value={d.findings.byState.likely} hint="Indício — validar manualmente" to="/achados?estado=likely" />
              <StatTile label="Pendentes de triagem" value={d.findings.openConfirmedOrLikely} hint="Confirmadas e prováveis em aberto" to="/achados?triagem=open" />
              <StatTile
                label="Cobertura média"
                to="/rotas"
                value={d.coverage.avgPct == null ? "—" : `${d.coverage.avgPct}%`}
                hint={d.coverage.avgPct == null ? "Sem scans com escopo registrado" : `${d.coverage.scansWithScope} scan(s) com escopo`}
              />
            </div>

            {priorities.length > 0 && (
              <section className="panel" aria-labelledby="h-prio">
                <div className="panel-head">
                  <div>
                    <h2 id="h-prio">Comece por aqui</h2>
                    <p className="panel-sub">Os achados em aberto mais graves, confirmados primeiro.</p>
                  </div>
                  <Link className="btn ghost sm" to="/achados?triagem=open">Ver todos os achados</Link>
                </div>
                <ul className="priority-list">
                  {priorities.map((f) => (
                    <li key={f.rowId}>
                      <SevBadge severity={f.severity} />
                      <div className="priority-main">
                        <Link to={`/achados/${f.rowId}`} className="row-link">{f.title}</Link>
                        <div className="cell-sub"><span className="mono">{assetLabel(f.asset)}</span> · {f.targetName}</div>
                      </div>
                      <StateBadge state={f.state} short />
                    </li>
                  ))}
                </ul>
              </section>
            )}

            <div className="grid-2">
              <section className="panel" aria-labelledby="h-sev">
                <h2 id="h-sev">Achados por severidade</h2>
                <p className="panel-sub">Vulnerabilidades confirmadas e prováveis ({problems}).</p>
                {problems > 0 ? (
                  <StackedBar segments={severity} label="Achados por severidade" />
                ) : (
                  <p className="muted">Nenhuma vulnerabilidade confirmada ou provável nos scans mais recentes.</p>
                )}
              </section>

              <section className="panel" aria-labelledby="h-state">
                <h2 id="h-state">Resultado das verificações</h2>
                <p className="panel-sub">Todas as verificações do último scan de cada projeto, por estado.</p>
                <Donut segments={states} label="Verificações por estado" center={{ value: totalChecks, caption: "verificações" }} />
              </section>

              <section className="panel" aria-labelledby="h-cat">
                <h2 id="h-cat">Achados por categoria</h2>
                <p className="panel-sub">Confirmadas e prováveis, por categoria de vulnerabilidade.</p>
                {d.findings.byCategory.length > 0 ? (
                  <BarList
                    label="Achados por categoria"
                    rows={d.findings.byCategory.map((c) => ({
                      key: c.category,
                      label: CATEGORY_LABEL[c.category] ?? c.category,
                      parts: [
                        { tone: "crit", value: c.vulnerable, label: "Confirmadas" },
                        { tone: "high", value: c.likely, label: "Prováveis" },
                      ],
                    }))}
                  />
                ) : (
                  <p className="muted">Sem achados para agrupar.</p>
                )}
              </section>

              <section className="panel" aria-labelledby="h-routes">
                <h2 id="h-routes">Rotas conhecidas, testadas e pendentes</h2>
                <p className="panel-sub">
                  Conhecidas pela spec, pelo código ou pela configuração do projeto. <Link to="/rotas">Ver detalhes</Link>
                </p>
                {d.routes ? (
                  <>
                    <div className="mini-stats">
                      <div><b>{d.routes.known}</b><span>conhecidas</span></div>
                      <div><b>{d.routes.tested}</b><span>testadas</span></div>
                      <div><b>{d.routes.pending}</b><span>pendentes</span></div>
                    </div>
                    <StackedBar
                      label="Rotas"
                      segments={[
                        { key: "tested", label: "Testadas", value: d.routes.tested, tone: "accent" },
                        { key: "pending", label: "Pendentes", value: d.routes.pending, tone: "na" },
                      ]}
                    />
                  </>
                ) : (
                  <p className="muted">Indisponível: os scans existentes são anteriores ao registro de escopo. Rode um novo scan.</p>
                )}
              </section>
            </div>

            <section className="panel" aria-labelledby="h-trend">
              <h2 id="h-trend">Evolução entre execuções</h2>
              {d.trend.length >= 2 ? (
                <TrendChart
                  points={d.trend.map((t) => ({
                    id: t.scanId, date: formatDate(t.createdAt).slice(0, 5), score: t.score,
                    vulnerable: t.vulnerable, likely: t.likely, coveragePct: t.coveragePct,
                  }))}
                />
              ) : (
                <p className="muted">{d.trendNote ?? "Sem execuções suficientes para comparar."}</p>
              )}
            </section>

            <details className="panel definitions">
              <summary>Como as métricas são calculadas</summary>
              <ul>
                <li><b>Confirmada</b>: a condição da falha foi observada e comprovada. <b>Provável</b>: há indício parcial e a validação é manual.</li>
                <li><b>Cobertura</b>: verificações executadas ÷ verificações aplicáveis ao projeto. Verificações que exigem login, spec ou autorização e não rodaram reduzem a cobertura.</li>
                <li><b>Rota conhecida</b>: aparece na spec, no código ou na configuração. <b>Testada</b>: ao menos uma verificação obteve resposta dela. <b>Pendente</b>: conhecida, mas sem teste.</li>
                <li>Os totais são os mesmos das listas em <Link to="/achados">Achados de segurança</Link> e <Link to="/rotas">Rotas e verificações</Link>.</li>
                <li>Aprovado significa “nenhuma falha encontrada no que foi testado” — não é garantia de que o sistema esteja protegido.</li>
              </ul>
            </details>
          </>
        )}
      </AsyncView>
    </div>
  );
}
