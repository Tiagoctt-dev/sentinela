import { useState } from "react";
import { Link } from "react-router-dom";
import { api, Coverage, OwaspCheck, OwaspItem } from "../api/client";
import AsyncView from "../components/ui/AsyncView";
import { SevBadge } from "../components/ui/Badge";
import PageHeader from "../components/ui/PageHeader";
import { useAsync } from "../hooks/useAsync";

const coverageLabel: Record<Coverage, { text: string; pill: string; help: string }> = {
  coberto: { text: "Cobertura ampla", pill: "pill-ok", help: "Há verificações com prova direta cobrindo a superfície típica do risco." },
  parcial: { text: "Cobertura parcial", pill: "pill-warn", help: "Há verificação, mas limitada a rotas configuradas, heurística, um único caso ou só indício." },
  nao_coberto: { text: "Sem verificação", pill: "pill-na", help: "Nenhuma verificação implementada para este risco." },
};

function CheckDetail({ c }: { c: OwaspCheck }) {
  return (
    <div className="check-row">
      <div className="check-top">
        <span className="mono check-id">{c.id}</span>
        <SevBadge severity={c.severity} />
        <span className="badge badge-file">{c.kind === "static" ? "código" : "ao vivo"}</span>
        {c.proof && (
          <span className={`conf-badge conf-${c.proof}`} title="Quanto uma falha desta verificação prova">
            {c.proof === "confirmed" ? "prova direta" : "indício"}
          </span>
        )}
        {c.needsConfig && <span className="badge badge-custom" title="Precisa de rotas ou credenciais de teste no projeto; sem isso aparece como não executada.">requer configuração</span>}
      </div>
      <div className="check-title">{c.title}</div>
      <div className="check-how">{c.how}</div>
      <details className="check-more">
        <summary>Critérios, pré-requisitos e limitações</summary>
        <dl className="kv">
          {c.objective && <div><dt>Objetivo</dt><dd>{c.objective}</dd></div>}
          {c.prerequisites && <div><dt>Pré-requisitos</dt><dd>{c.prerequisites}</dd></div>}
          {c.passWhen && <div><dt>Aprova quando</dt><dd>{c.passWhen}</dd></div>}
          {c.failWhen && <div><dt>Reprova quando</dt><dd>{c.failWhen}</dd></div>}
          {c.severityReason && <div><dt>Severidade</dt><dd>{c.severityReason}</dd></div>}
          {c.limitations && <div><dt>Limitações</dt><dd>{c.limitations}</dd></div>}
          {c.references.length > 0 && (
            <div>
              <dt>Referências</dt>
              <dd>
                <ul className="ref-list">
                  {c.references.map((r) => (
                    <li key={r.url}><a href={r.url} target="_blank" rel="noreferrer noopener">{r.label}</a></li>
                  ))}
                </ul>
              </dd>
            </div>
          )}
        </dl>
      </details>
    </div>
  );
}

function ItemCard({ item, open, onToggle }: { item: OwaspItem; open: boolean; onToggle: () => void }) {
  const cov = coverageLabel[item.coverage];
  const { pass, fail, warn } = item.stats;
  return (
    <section className="policy-card">
      <button className="policy-head" onClick={onToggle} aria-expanded={open}>
        <span className="policy-head-main">
          <span className="policy-code mono">{item.id}</span>
          <span className="policy-name">{item.name}</span>
          <span className="policy-desc">{item.description}</span>
        </span>
        <span className="policy-head-side">
          <span className={`pill ${cov.pill}`} title={cov.help}>{cov.text}</span>
          {item.stats.open > 0 && <span className="pill pill-fail">{item.stats.open} em aberto</span>}
          <span className="chev" aria-hidden="true">{open ? "▾" : "▸"}</span>
        </span>
      </button>

      {open && (
        <div className="policy-body">
          {item.coverageNote && <p className="policy-note"><b>Limites da cobertura:</b> {item.coverageNote}</p>}

          {item.checks.length > 0 && (
            <>
              <h3 className="small-title">Verificações ({item.checks.length})</h3>
              <div className="check-list">
                {item.checks.map((c) => <CheckDetail key={c.id} c={c} />)}
              </div>
            </>
          )}

          {pass + fail + warn > 0 ? (
            <div className="mini-stats">
              <div><b>{pass}</b><span>aprovadas</span></div>
              <div><b>{warn}</b><span>prováveis</span></div>
              <div><b>{fail}</b><span>confirmadas</span></div>
            </div>
          ) : (
            item.checks.length > 0 && <p className="muted small">Nenhum scan avaliou este controle ainda.</p>
          )}

          {item.openFindings.length > 0 && (
            <>
              <h3 className="small-title">Achados em aberto neste controle</h3>
              <ul className="policy-violation-list">
                {item.openFindings.map((f) => (
                  <li key={f.rowId}>
                    <SevBadge severity={f.severity} /> <Link to={`/achados/${f.rowId}`}>{f.title}</Link> <span className="muted">— {f.targetName}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </section>
  );
}

export default function PoliciesPage() {
  const catalog = useAsync(() => api.getPolicyCatalog(), []);
  const [openId, setOpenId] = useState<string | null>(null);
  const c = catalog.data;

  return (
    <div>
      <PageHeader
        title="Políticas"
        description="O que o Sentinela verifica em cada scan: a regra de aprovação e a cobertura do OWASP API Security Top 10 (2023), com critérios e limitações de cada verificação."
      />
      <AsyncView loading={catalog.loading} error={catalog.error} onRetry={catalog.reload} hasData={!!c}>
        {c && (
          <>
            <section className="panel" aria-labelledby="h-gate">
              <h2 id="h-gate">Regra de aprovação — {c.gate.name}</h2>
              <p>{c.gate.summary}</p>
              <div className="verdict-grid">
                {c.gate.verdicts.map((v) => (
                  <div key={v.label} className="verdict-card">
                    <span className="stat-label">{v.range}</span>
                    <b>{v.label}</b>
                  </div>
                ))}
              </div>
              <ul className="policy-list">
                {c.gate.scoring.map((line) => <li key={line}>{line}</li>)}
              </ul>
            </section>

            <h2 className="section-heading">Cobertura do OWASP API Top 10 (2023)</h2>
            <p className="panel-sub">
              {c.summary.covered} com cobertura ampla · {c.summary.partial} parcial · {c.summary.notCovered} sem verificação — {c.summary.checks} verificações no total.
              Nenhum item é marcado como coberto só por existir uma verificação com o nome correspondente: abra o item para ver o que é testado e o que não é.
            </p>
            {c.items.map((item) => (
              <ItemCard key={item.id} item={item} open={openId === item.id} onToggle={() => setOpenId(openId === item.id ? null : item.id)} />
            ))}
            <p className="muted small">Políticas customizadas (por projeto, severidade mínima, múltiplas condições) ainda não estão disponíveis.</p>
          </>
        )}
      </AsyncView>
    </div>
  );
}
