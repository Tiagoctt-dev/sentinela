import { ReactNode, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, FindingWithContext, Resolution } from "../api/client";
import AsyncView from "../components/ui/AsyncView";
import { SevBadge, StateBadge } from "../components/ui/Badge";
import Button from "../components/ui/Button";
import { Field } from "../components/ui/Form";
import PageHeader from "../components/ui/PageHeader";
import { useToast } from "../components/ui/ToastContext";
import { useAsync } from "../hooks/useAsync";
import { assetLabel, CATEGORY_LABEL, formatDate, RESOLUTION_LABEL, stateMeta } from "../lib/results";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="detail-section">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export default function FindingDetailPage() {
  const { rowId } = useParams<{ rowId: string }>();
  const toast = useToast();
  const query = useAsync<FindingWithContext>(() => api.getFinding(rowId ?? ""), [rowId]);
  const f = query.data;
  const [note, setNote] = useState("");
  const [noteError, setNoteError] = useState("");
  const [saving, setSaving] = useState<Resolution | null>(null);
  const [expiresInDays, setExpiresInDays] = useState("90");

  useEffect(() => {
    setNote(f?.resolutionNote ?? "");
    setNoteError("");
  }, [f?.rowId, f?.resolutionNote]);

  async function triage(resolution: Resolution) {
    if (!f) return;
    if (resolution === "risk_accepted" && !note.trim()) {
      setNoteError("Aceitar o risco exige uma justificativa.");
      return;
    }
    setNoteError("");
    setSaving(resolution);
    try {
      const updated = await api.updateFinding(f.rowId, {
        resolution,
        resolutionNote: note.trim() || undefined,
        ...(resolution === "risk_accepted" && expiresInDays ? { expiresInDays: Number(expiresInDays) } : {}),
      });
      query.setData({ ...updated, history: f.history }); // o histórico não muda com a triagem
      toast.success(`Triagem atualizada: ${RESOLUTION_LABEL[resolution].toLowerCase()}.`);
    } catch (e) {
      toast.error(e);
    } finally {
      setSaving(null);
    }
  }

  const meta = f?.meta ?? null;
  const sm = f ? stateMeta(f.state) : null;

  return (
    <div>
      <PageHeader
        title={f ? f.title : "Achado"}
        crumbs={[{ label: "Achados de segurança", to: "/achados" }, { label: f?.id ?? "Detalhe" }]}
      />

      <AsyncView loading={query.loading} error={query.error} onRetry={query.reload} hasData={!!f}>
        {f && sm && (
          <>
            <div className="badge-row">
              <SevBadge severity={f.severity} />
              <StateBadge state={f.state} />
              {f.owasp && <span className="owasp mono">{f.owasp}</span>}
              <span className="mono muted">{f.id}</span>
            </div>

            <div className="detail-layout">
              <div className="detail-main">
                {meta?.summary && (
                  <Section title="Resumo executivo">
                    <p>{meta.summary}</p>
                  </Section>
                )}

                <Section title="Ativo afetado">
                  <dl className="kv">
                    <div><dt>Projeto</dt><dd>{f.targetName}</dd></div>
                    {f.asset?.host && <div><dt>Domínio</dt><dd className="mono">{f.asset.host}</dd></div>}
                    <div><dt>Endpoint</dt><dd className="mono">{assetLabel(f.asset)}</dd></div>
                    {f.asset?.param && <div><dt>Parâmetro</dt><dd className="mono">{f.asset.param}</dd></div>}
                    {f.asset?.httpStatus != null && <div><dt>Código HTTP</dt><dd className="mono">{f.asset.httpStatus}</dd></div>}
                  </dl>
                </Section>

                <Section title="O que foi observado">
                  {f.detail && <p>{f.detail}</p>}
                  {meta?.technical && <p className="muted">{meta.technical}</p>}
                  {f.evidence ? (
                    <div className="evidence" aria-label="Evidência">
                      <div className="evidence-head">Evidência — requisição e resposta (valores sensíveis são mascarados)</div>
                      <pre>{f.evidence}</pre>
                    </div>
                  ) : (
                    <p className="muted">Esta verificação não registrou evidência textual.</p>
                  )}
                </Section>

                {(f.recommendation || f.aiRec) && (
                  <Section title="Recomendação de correção">
                    {f.recommendation && <p>{f.recommendation}</p>}
                    {f.aiRec &&
                      Object.entries(f.aiRec).map(([key, rec]) => (
                        <div className="ai-rec" key={key}>
                          <div className="ai-rec-head">
                            <span className="ai-badge">{rec.provider}</span>
                            {rec.prioridade && <span className={`prio ${rec.prioridade}`}>prioridade {rec.prioridade}</span>}
                          </div>
                          {rec.risco && (
                            <p>
                              <b>Risco:</b> {rec.risco}
                            </p>
                          )}
                          {rec.acao && <p>{rec.acao}</p>}
                        </div>
                      ))}
                  </Section>
                )}

                {f.history && f.history.windowScans > 1 && (
                  <Section title="Histórico deste achado">
                    <p className="muted">
                      {f.history.regression
                        ? "Este problema estava corrigido e voltou a aparecer (regressão). "
                        : ""}
                      Visto em {f.history.occurrences} de {f.history.windowScans} execuções recentes
                      {f.history.firstSeenAt ? `, desde ${formatDate(f.history.firstSeenAt)}` : ""}.
                    </p>
                    <ol className="history-line" aria-label="Estado em cada execução, da mais antiga para a mais recente">
                      {f.history.timeline.map((h) => {
                        const label = h.state === null ? "não apareceu" : stateMeta(h.state).label;
                        return (
                          <li key={h.scanId} className={`history-dot state-${h.state ?? "absent"}`}>
                            <Link to={`/scans/${h.scanId}`} title={`${formatDate(h.createdAt)} — ${label}`}>
                              <span className="history-date">{formatDate(h.createdAt)}</span>
                              <span className="history-state">{label}</span>
                            </Link>
                          </li>
                        );
                      })}
                    </ol>
                  </Section>
                )}

                <details className="detail-more">
                  <summary>Entenda o contexto: impacto, exploração, severidade e limitações</summary>
                  <div className="detail-more-body">
                {meta?.impact && (
                  <Section title="Impacto">
                    <p>{meta.impact}</p>
                  </Section>
                )}

                {(meta?.exploitation || meta?.prerequisites) && (
                  <Section title="Cenário de exploração e condições">
                    {meta.exploitation && <p>{meta.exploitation}</p>}
                    {meta.prerequisites && (
                      <p className="muted">
                        <b>Condições necessárias:</b> {meta.prerequisites}
                      </p>
                    )}
                  </Section>
                )}

                <Section title="Severidade e prova">
                  <dl className="kv">
                    <div>
                      <dt>Severidade</dt>
                      <dd>
                        <SevBadge severity={f.severity} /> {meta?.severityReason}
                      </dd>
                    </div>
                    <div>
                      <dt>Situação</dt>
                      <dd>
                        <StateBadge state={f.state} /> <span className="muted">{sm.help} {meta?.proof === "confirmed" ? "Esta verificação observa a própria condição da falha." : "Esta verificação produz um indício; a confirmação exige validação manual."}</span>
                      </dd>
                    </div>
                  </dl>
                </Section>

                {(meta?.limitations || meta?.scopeNote) && (
                  <Section title="Limitações">
                    {meta.limitations && <p>{meta.limitations}</p>}
                    {meta.scopeNote && <p className="muted">{meta.scopeNote}</p>}
                  </Section>
                )}

                  </div>
                </details>

                {meta?.references && meta.references.length > 0 && (
                  <Section title="Referências">
                    <ul className="ref-list">
                      {meta.references.map((r) => (
                        <li key={r.url}>
                          <a href={r.url} target="_blank" rel="noreferrer noopener">
                            {r.label}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </Section>
                )}

                <Section title="Rastreabilidade">
                  <dl className="kv">
                    <div>
                      <dt>Execução</dt>
                      <dd>
                        <Link to={`/scans/${f.scanId}`} className="mono">{f.scanId.slice(0, 8)}</Link> · {formatDate(f.createdAt)}
                      </dd>
                    </div>
                    <div>
                      <dt>Política</dt>
                      <dd>
                        <span className="mono">{f.id}</span> · <Link to="/politicas">ver critérios</Link>
                      </dd>
                    </div>
                    <div><dt>Categoria</dt><dd>{CATEGORY_LABEL[f.category] ?? f.category}</dd></div>
                    <div><dt>Origem</dt><dd>{f.source === "static" ? "Análise de código" : "Teste dinâmico"}</dd></div>
                    {meta?.passWhen && <div><dt>Aprova quando</dt><dd>{meta.passWhen}</dd></div>}
                    {meta?.failWhen && <div><dt>Reprova quando</dt><dd>{meta.failWhen}</dd></div>}
                  </dl>
                  <p>
                    <Link to={`/scans/${f.scanId}/rotas`}>Ver todas as verificações desta execução →</Link>
                  </p>
                </Section>
              </div>

              <aside className="detail-side" aria-label="Triagem">
                <h2>Triagem</h2>
                <p className="muted small">
                  Estado de validação: <b>{RESOLUTION_LABEL[f.resolution] ?? f.resolution}</b>
                </p>
                {f.resolution === "risk_accepted" && (
                  <p className="small" role="status">
                    Risco aceito{f.resolutionBy ? ` por ${f.resolutionBy}` : ""}
                    {f.resolutionExpiresAt ? ` até ${formatDate(f.resolutionExpiresAt)}. Depois disso o achado volta para “aberto”.` : " sem prazo de validade."}
                  </p>
                )}
                <Field label="Nota" optional hint="Obrigatória ao aceitar o risco.">
                  <textarea rows={4} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Justificativa, link do chamado, etc." aria-invalid={!!noteError} />
                </Field>
                {noteError && (
                  <p className="error" role="alert">
                    {noteError}
                  </p>
                )}
                <Field label="Validade do aceite de risco" hint="O risco aceito vence e o achado reabre sozinho — assim ele não fica esquecido.">
                  <select value={expiresInDays} onChange={(e) => setExpiresInDays(e.target.value)}>
                    <option value="30">30 dias</option>
                    <option value="90">90 dias</option>
                    <option value="180">180 dias</option>
                    <option value="365">1 ano</option>
                    <option value="">Sem prazo</option>
                  </select>
                </Field>
                <div className="side-actions">
                  <Button onClick={() => triage("resolved")} loading={saving === "resolved"} loadingLabel="Salvando…" disabled={!!saving || f.resolution === "resolved"}>
                    Marcar como resolvido
                  </Button>
                  <Button variant="ghost" onClick={() => triage("risk_accepted")} loading={saving === "risk_accepted"} loadingLabel="Salvando…" disabled={!!saving || f.resolution === "risk_accepted"}>
                    Aceitar risco
                  </Button>
                  {f.resolution !== "open" && (
                    <Button variant="ghost" onClick={() => triage("open")} loading={saving === "open"} loadingLabel="Salvando…" disabled={!!saving}>
                      Reabrir
                    </Button>
                  )}
                </div>
                <p className="muted small">
                  Issues no GitHub são criadas automaticamente a cada scan, só para vulnerabilidades críticas confirmadas, se houver uma integração ativa.
                </p>
              </aside>
            </div>
          </>
        )}
      </AsyncView>
    </div>
  );
}
