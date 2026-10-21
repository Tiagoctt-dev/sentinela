import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, ScanComparison, ScanDetail as ScanDetailT } from "../api/client";
import CategoryBars from "../components/CategoryBars";
import FindingCard from "../components/FindingCard";
import Gauge from "../components/Gauge";
import { useScanRun } from "../components/ScanRunContext";
import Button from "../components/ui/Button";
import ProgressIndicator, { useElapsed } from "../components/ui/ProgressIndicator";

const order = ["FAIL", "WARN", "PASS", "SKIP"];
const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { run, active } = useScanRun();
  const [scan, setScan] = useState<ScanDetailT | null>(null);
  const [error, setError] = useState("");
  const [rerunning, setRerunning] = useState(false);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [comparing, setComparing] = useState(false);
  const elapsed = useElapsed(rerunning);

  useEffect(() => {
    if (!id) return;
    api
      .getScan(id)
      .then(setScan)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Erro ao carregar o scan."));
  }, [id]);

  if (error) return <p className="error">{error}</p>;
  if (!scan) return <p className="muted">Carregando…</p>;

  async function rerun() {
    if (!scan) return;
    setRerunning(true);
    try {
      const fresh = await run(scan.targetName, () => api.runScan({ targetId: scan.targetId }));
      navigate(`/scans/${fresh.id}`);
    } catch {
      // erro já mostrado via toast
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
      setError(e instanceof ApiError ? e.message : "Erro ao comparar.");
    } finally {
      setComparing(false);
    }
  }

  const sorted = [...scan.findings].sort(
    (a, b) => order.indexOf(a.status) - order.indexOf(b.status) || sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity)
  );
  const t = scan.totals;
  const ai = scan.ai;
  const policy = scan.policy;

  return (
    <div>
      <Link to="/scans" className="back-link">
        ← scans
      </Link>

      <div className="detail-head">
        <div>
          <h1>{scan.targetName}</h1>
          <div className="meta mono">
            {new Date(scan.createdAt).toLocaleString("pt-BR")} · análise {scan.mode}{scan.origin === "agendado" ? " · agendado" : scan.createdBy ? ` · por ${scan.createdBy}` : ""}
          </div>
        </div>
        <div className="detail-actions">
          <Button variant="ghost" onClick={compare} loading={comparing} loadingLabel="Comparando…">
            Comparar com anterior
          </Button>
          <Button variant="ghost" onClick={() => window.print()} title="Abre a impressão — escolha 'Salvar como PDF'">
            Exportar PDF
          </Button>
          {rerunning ? <ProgressIndicator elapsedMs={elapsed} /> : (
            <Button onClick={rerun} disabled={!!active}>
              Rodar novamente
            </Button>
          )}
        </div>
      </div>

      {comparison && (
        <div className="compare-panel">
          {!comparison.previous ? (
            <p className="muted">Este é o primeiro scan deste projeto — não há execução anterior para comparar.</p>
          ) : (
            <>
              <div className="compare-head">
                <b>Comparação com o scan de {new Date(comparison.previous.createdAt).toLocaleString("pt-BR")}</b>
                <span className={`pill ${(comparison.delta ?? 0) > 0 ? "pill-ok" : (comparison.delta ?? 0) < 0 ? "pill-fail" : "pill-na"}`}>
                  score {comparison.previous.overall} → {scan.overall} ({(comparison.delta ?? 0) > 0 ? "+" : ""}{comparison.delta})
                </span>
                <button className="ghost sm no-print" onClick={() => setComparison(null)}>Fechar</button>
              </div>
              <div className="compare-cols">
                <div>
                  <div className="compare-title c-fail">Novos problemas ({comparison.new?.length})</div>
                  {comparison.new?.map((f) => <Link key={f.rowId} to={`/achados/${f.rowId}`}>{f.title}</Link>)}
                  {!comparison.new?.length && <span className="muted small">Nenhum.</span>}
                </div>
                <div>
                  <div className="compare-title c-ok">Corrigidos ({comparison.fixed?.length})</div>
                  {comparison.fixed?.map((f) => <span key={f.rowId + "f"}>{f.title}</span>)}
                  {!comparison.fixed?.length && <span className="muted small">Nenhum.</span>}
                </div>
                <div>
                  <div className="compare-title c-warn">Persistem ({comparison.persisting}) · Pioraram ({comparison.worse?.length})</div>
                  {comparison.worse?.map((f) => <Link key={f.rowId + "w"} to={`/achados/${f.rowId}`}>{f.title}</Link>)}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      <div className="top">
        <div>
          <Gauge score={scan.overall} verdict={scan.verdict} />
          {policy && (
            <div className="top-policy">
              {policy.passed ? "Aprovado" : "Reprovado"} pela política <b>{policy.policyName}</b>: {policy.reason}
            </div>
          )}
        </div>
        <div>
          <div className="counts mono">
            <span className="c-ok">
              ✔ <b>{t.PASS}</b> ok
            </span>
            <span className="c-fail">
              ✘ <b>{t.FAIL}</b> falhas
            </span>
            <span className="c-warn">
              ▲ <b>{t.WARN}</b> atenção
            </span>
            <span className="c-skip">
              – <b>{t.SKIP}</b> pulados
            </span>
          </div>
          <CategoryBars categories={scan.categories} />
        </div>
      </div>

      {policy && (
        <div className={`policy-banner ${policy.passed ? "pass" : "fail"}`}>
          {policy.passed ? "✔" : "✘"} {policy.passed ? "Aprovado" : "Reprovado"} pela política "{policy.policyName}" —{" "}
          {policy.reason}
        </div>
      )}

      {ai && ai.length > 0 && (
        <div className="ai-grid">
          {ai.map((o) => (
            <div key={o.key} className={`ai-panel ${o.enabled ? "" : "disabled"}`}>
              <div className="ai-head">
                🧠 {o.provider}
                {o.model && <span className="ai-meta mono">{o.model}</span>}
              </div>
              {o.enabled && o.summary ? <p>{o.summary}</p> : <p className="muted">{o.reason}</p>}
            </div>
          ))}
        </div>
      )}

      <h2>Achados</h2>
      <div className="h2sub">Falhas e avisos primeiro, ordenados por severidade. Clique num achado pra ver a evidência completa e triar.</div>
      {sorted.map((f) => (
        <FindingCard key={f.rowId} f={f} />
      ))}
    </div>
  );
}
