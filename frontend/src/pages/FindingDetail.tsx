import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError, FindingWithContext, OwaspItem, Resolution } from "../api/client";
import Button from "../components/ui/Button";
import { useToast } from "../components/ui/ToastContext";

const sevClass = (s: string) => ({ CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" }[s] || "info");

export default function FindingDetailPage() {
  const { rowId } = useParams<{ rowId: string }>();
  const toast = useToast();
  const [finding, setFinding] = useState<FindingWithContext | null>(null);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [owaspItem, setOwaspItem] = useState<OwaspItem | null>(null);

  const load = () => {
    if (!rowId) return;
    api
      .getFinding(rowId)
      .then((f) => {
        setFinding(f);
        setNote(f.resolutionNote || "");
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Erro ao carregar o achado."));
  };

  useEffect(load, [rowId]);

  useEffect(() => {
    if (!finding?.owasp) return;
    api
      .getPolicyCatalog()
      .then((c) => setOwaspItem(c.items.find((i) => i.id === finding.owasp) ?? null))
      .catch(() => {});
  }, [finding?.owasp]);

  async function setResolution(resolution: Resolution) {
    if (!rowId) return;
    setSaving(true);
    try {
      const updated = await api.updateFinding(rowId, { resolution, resolutionNote: note || undefined });
      setFinding(updated);
    } catch (e) {
      toast.error(e);
    } finally {
      setSaving(false);
    }
  }

  if (error) return <p className="error">{error}</p>;
  if (!finding) return <p className="muted">Carregando…</p>;

  return (
    <div>
      <Link to={`/scans/${finding.scanId}`} className="back-link">
        ← scan de {finding.targetName}
      </Link>

      <div className="fd-badges">
        <span className={`sev ${sevClass(finding.severity)}`}>{finding.severity}</span>
        {finding.owasp && <span className="owasp mono">{finding.owasp}</span>}
        <span className="fid mono">{finding.id}</span>
      </div>
      <h1 className="fd-title">{finding.title}</h1>
      {finding.detail && <p className="fd-desc">{finding.detail}</p>}

      <div className="fd-layout">
        <div>
          {finding.evidence && (
            <div className="fd-panel">
              <div className="fd-panel-head">
                <span>Evidência — requisição e resposta</span>
              </div>
              <div className="fd-code">{finding.evidence}</div>
            </div>
          )}

          {owaspItem && (
            <div className="fd-panel">
              <div className="fd-panel-head">
                <span>Por que isso importa — {owaspItem.id}</span>
              </div>
              <div className="fd-about">
                <b>{owaspItem.name}</b>
                <p>{owaspItem.description}</p>
                <Link to="/politicas">Ver como o Sentinela testa este risco →</Link>
              </div>
            </div>
          )}

          {finding.aiRec && (
            <div className="ai-grid" style={{ marginTop: 0 }}>
              {Object.entries(finding.aiRec).map(([key, rec]) => (
                <div className="ai-panel" style={{ marginTop: 0 }} key={key}>
                  <div className="ai-head">
                    🧠 {rec.provider}
                    {rec.prioridade && <span className={`prio ${rec.prioridade}`}>prioridade {rec.prioridade}</span>}
                  </div>
                  {rec.risco && (
                    <p>
                      <b>Risco:</b> {rec.risco}
                    </p>
                  )}
                  <p>{rec.acao}</p>
                </div>
              ))}
            </div>
          )}

          {!finding.aiRec && finding.recommendation && (
            <div className="fd-panel">
              <div className="fd-panel-head">
                <span>Como corrigir</span>
              </div>
              <div className="fd-code">{finding.recommendation}</div>
            </div>
          )}
        </div>

        <div className="fd-side">
          <div className="fd-field">
            <div className="k">Status</div>
            <select value={finding.resolution} onChange={(e) => setResolution(e.target.value as Resolution)} disabled={saving}>
              <option value="open">Aberto</option>
              <option value="resolved">Resolvido</option>
              <option value="risk_accepted">Risco aceito</option>
            </select>
          </div>
          <div className="fd-field">
            <div className="k">Projeto</div>
            <div className="v">{finding.targetName}</div>
          </div>
          <div className="fd-field">
            <div className="k">Categoria</div>
            <div className="v">{finding.category}</div>
          </div>
          <div className="fd-field">
            <div className="k">Regra</div>
            <div className="v mono">{finding.id}</div>
          </div>
          <div className="fd-field">
            <div className="k">Visto em</div>
            <div className="v">{new Date(finding.createdAt).toLocaleString("pt-BR")}</div>
          </div>
          <div className="fd-field">
            <div className="k">Nota (opcional)</div>
            <textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Justificativa, link do issue, etc." />
          </div>
          <div className="fd-actions">
            <Button onClick={() => setResolution("resolved")} disabled={saving || finding.resolution === "resolved"}>
              Marcar como resolvido
            </Button>
            <Button variant="ghost" disabled title="Ainda não disponível — roadmap">
              Criar issue no repositório (em breve)
            </Button>
            <Button variant="ghost" onClick={() => setResolution("risk_accepted")} disabled={saving || finding.resolution === "risk_accepted"}>
              Aceitar risco com justificativa
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
