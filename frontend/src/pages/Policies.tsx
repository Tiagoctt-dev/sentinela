import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Coverage, OwaspItem, PolicyCatalog } from "../api/client";
import { SevBadge } from "../components/ui/Badge";
import { useToast } from "../components/ui/ToastContext";

const coverageLabel: Record<Coverage, { text: string; pill: string }> = {
  coberto: { text: "coberto", pill: "pill-ok" },
  parcial: { text: "cobertura parcial", pill: "pill-warn" },
  nao_coberto: { text: "ainda não testado", pill: "pill-na" },
};

function ItemCard({ item, open, onToggle }: { item: OwaspItem; open: boolean; onToggle: () => void }) {
  const cov = coverageLabel[item.coverage];
  const { pass, fail, warn } = item.stats;
  return (
    <div className="policy-card">
      <div className="policy-card-head policy-toggle" onClick={onToggle} role="button" tabIndex={0}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onToggle()} aria-expanded={open}>
        <div style={{ minWidth: 0 }}>
          <div className="policy-code mono">{item.id}</div>
          <h3>{item.name}</h3>
          <p>{item.description}</p>
        </div>
        <div className="policy-head-side">
          <span className={`pill ${cov.pill}`}>{cov.text}</span>
          {item.stats.open > 0 && <span className="pill pill-fail">{item.stats.open} aberto(s)</span>}
          <span className="chev">{open ? "▾" : "▸"}</span>
        </div>
      </div>

      {open && (
        <div className="policy-body">
          {item.coverageNote && <p className="policy-note">{item.coverageNote}</p>}

          {item.checks.length > 0 && (
            <>
              <div className="h2sub" style={{ marginTop: 14 }}>
                Como o Sentinela testa ({item.checks.length} verificação(ões))
              </div>
              <div className="check-list">
                {item.checks.map((c) => (
                  <div key={c.id} className="check-row">
                    <div className="check-top">
                      <span className="mono check-id">{c.id}</span>
                      <SevBadge severity={c.severity} />
                      <span className="badge badge-file">{c.kind === "static" ? "código" : "ao vivo"}</span>
                      {c.needsConfig && <span className="badge badge-custom" title="Precisa de rotas/credenciais de teste no projeto; sem isso é pulada.">requer config</span>}
                    </div>
                    <div className="check-title">{c.title}</div>
                    <div className="check-how">{c.how}</div>
                  </div>
                ))}
              </div>
            </>
          )}

          {(pass + fail + warn > 0) && (
            <div className="policy-stats" style={{ marginTop: 16 }}>
              <div className="stat-card">
                <div className="stat-label">Passou</div>
                <div className="stat-value" style={{ color: "var(--ok)" }}>{pass}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Alertas</div>
                <div className="stat-value" style={{ color: "var(--high)" }}>{warn}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Falhas</div>
                <div className={`stat-value ${fail > 0 ? "crit" : ""}`}>{fail}</div>
              </div>
            </div>
          )}

          {item.openFindings.length > 0 && (
            <>
              <div className="h2sub" style={{ marginTop: 16 }}>Achados abertos neste controle (scan mais recente de cada projeto)</div>
              <div className="policy-violation-list">
                {item.openFindings.map((f) => (
                  <Link key={f.rowId} to={`/achados/${f.rowId}`}>
                    <SevBadge severity={f.severity} /> {f.title} — <span className="muted">{f.targetName}</span>
                  </Link>
                ))}
              </div>
            </>
          )}
          {item.stats.pass + item.stats.fail + item.stats.warn === 0 && item.checks.length > 0 && (
            <p className="muted small" style={{ marginTop: 12 }}>Nenhum scan avaliou este controle ainda.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function PoliciesPage() {
  const toast = useToast();
  const [catalog, setCatalog] = useState<PolicyCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [openId, setOpenId] = useState<string | null>(null);

  useEffect(() => {
    api
      .getPolicyCatalog()
      .then(setCatalog)
      .catch((e) => toast.error(e))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Políticas</h1>
          <div className="eyebrow">
            As regras que o Sentinela aplica em cada scan: quando um sistema é aprovado e quais riscos do OWASP API
            Top 10 são testados.
          </div>
        </div>
      </div>

      {loading && <p className="muted">Carregando…</p>}

      {catalog && (
        <>
          <h2 style={{ marginTop: 0 }}>1. Regra de aprovação</h2>
          <div className="policy-card">
            <h3>{catalog.gate.name}</h3>
            <p>{catalog.gate.summary}</p>
            <div className="verdict-grid">
              {catalog.gate.verdicts.map((v) => (
                <div key={v.label} className="stat-card">
                  <div className="stat-label">{v.range}</div>
                  <div style={{ fontWeight: 600 }}>{v.label}</div>
                </div>
              ))}
            </div>
            <ul className="policy-list">
              {catalog.gate.scoring.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>

          <h2>2. Controles OWASP API Security Top 10 (2023)</h2>
          <div className="h2sub">
            {catalog.summary.covered} cobertos · {catalog.summary.partial} parcialmente · {catalog.summary.notCovered} ainda
            não testados — {catalog.summary.checks} verificações no total. Clique num controle para ver o que é testado.
          </div>
          {catalog.items.map((item) => (
            <ItemCard key={item.id} item={item} open={openId === item.id} onToggle={() => setOpenId(openId === item.id ? null : item.id)} />
          ))}

          <p className="muted small" style={{ marginTop: 18 }}>
            Políticas customizadas (por projeto, severidade mínima, múltiplas condições) ainda não estão disponíveis.
          </p>
        </>
      )}
    </div>
  );
}
