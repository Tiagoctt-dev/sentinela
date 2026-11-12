// Gráficos em SVG/CSS sem dependências. Cada gráfico recebe dados reais, mostra os números como texto
// (a cor nunca é o único canal) e tem rótulo acessível. Sem dados, quem usa deve renderizar um estado vazio.

export interface Segment {
  key: string;
  label: string;
  value: number;
  tone: string; // classe de cor: crit | high | med | low | info | ok | warn | na | accent
}

const sum = (segs: Segment[]) => segs.reduce((n, s) => n + s.value, 0);

/** Barra empilhada horizontal com legenda numérica. */
export function StackedBar({ segments, label }: { segments: Segment[]; label: string }) {
  const total = sum(segments);
  const present = segments.filter((s) => s.value > 0);
  return (
    <div className="chart">
      <div className="stack-track" role="img" aria-label={`${label}: ${present.map((s) => `${s.label} ${s.value}`).join(", ") || "sem itens"}`}>
        {present.map((s) => (
          <div key={s.key} className={`stack-seg tone-bg-${s.tone}`} style={{ width: `${(s.value / total) * 100}%` }} title={`${s.label}: ${s.value}`} />
        ))}
      </div>
      <ul className="legend">
        {segments.map((s) => (
          <li key={s.key} className={s.value === 0 ? "zero" : ""}>
            <i className={`dot tone-bg-${s.tone}`} aria-hidden="true" /> {s.label} <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Lista de barras horizontais (categorias). */
export function BarList({
  rows, label,
}: {
  rows: { key: string; label: string; parts: { tone: string; value: number; label: string }[] }[];
  label: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.parts.reduce((n, p) => n + p.value, 0)));
  return (
    <ul className="bar-list" aria-label={label}>
      {rows.map((r) => {
        const total = r.parts.reduce((n, p) => n + p.value, 0);
        return (
          <li key={r.key}>
            <span className="bar-list-label">{r.label}</span>
            <span className="bar-list-track" aria-hidden="true">
              {r.parts.filter((p) => p.value > 0).map((p) => (
                <span key={p.label} className={`bar-list-seg tone-bg-${p.tone}`} style={{ width: `${(p.value / max) * 100}%` }} title={`${p.label}: ${p.value}`} />
              ))}
            </span>
            <span className="bar-list-value">
              {total} <small>{r.parts.filter((p) => p.value > 0).map((p) => `${p.value} ${p.label.toLowerCase()}`).join(" · ")}</small>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/** Rosca de estados. */
export function Donut({ segments, label, center }: { segments: Segment[]; label: string; center: { value: string | number; caption: string } }) {
  const total = sum(segments);
  const R = 52;
  const C = 2 * Math.PI * R;
  let offset = 0;
  return (
    <div className="chart donut-wrap">
      <svg viewBox="0 0 140 140" className="donut" role="img" aria-label={`${label}: ${segments.filter((s) => s.value).map((s) => `${s.label} ${s.value}`).join(", ")}`}>
        <circle cx="70" cy="70" r={R} fill="none" className="donut-track" strokeWidth="16" />
        {total > 0 &&
          segments.filter((s) => s.value > 0).map((s) => {
            const len = (s.value / total) * C;
            const el = (
              <circle
                key={s.key} cx="70" cy="70" r={R} fill="none" className={`tone-stroke-${s.tone}`} strokeWidth="16"
                strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset} transform="rotate(-90 70 70)"
              >
                <title>{`${s.label}: ${s.value}`}</title>
              </circle>
            );
            offset += len;
            return el;
          })}
        <text x="70" y="68" textAnchor="middle" className="donut-value">{center.value}</text>
        <text x="70" y="86" textAnchor="middle" className="donut-caption">{center.caption}</text>
      </svg>
      <ul className="legend vertical">
        {segments.map((s) => (
          <li key={s.key} className={s.value === 0 ? "zero" : ""}>
            <i className={`dot tone-bg-${s.tone}`} aria-hidden="true" /> {s.label} <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface TrendPoint {
  id: string;
  date: string;
  score: number;
  vulnerable: number;
  likely: number;
  coveragePct: number | null;
}

/** Evolução entre execuções: score (linha) e vulnerabilidades por execução (barras empilhadas). */
export function TrendChart({ points }: { points: TrendPoint[] }) {
  const W = 560, H = 190, padL = 34, padR = 12, padT = 12, padB = 26;
  const n = points.length;
  const x = (i: number) => padL + (n === 1 ? (W - padL - padR) / 2 : (i * (W - padL - padR)) / (n - 1));
  const yScore = (v: number) => padT + (1 - v / 100) * (H - padT - padB);
  const maxVuln = Math.max(1, ...points.map((p) => p.vulnerable + p.likely));
  const barW = Math.min(26, (W - padL - padR) / (n * 1.8));
  const yBar = (v: number) => padT + (1 - v / maxVuln) * (H - padT - padB);
  const base = H - padB;
  const line = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${yScore(p.score).toFixed(1)}`).join(" ");
  const first = points[0], last = points[n - 1];
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} className="trend" role="img"
        aria-label={`Evolução em ${n} execuções: score de ${first.score} para ${last.score}; vulnerabilidades confirmadas de ${first.vulnerable} para ${last.vulnerable}`}>
        {[0, 50, 100].map((g) => (
          <g key={g}>
            <line x1={padL} x2={W - padR} y1={yScore(g)} y2={yScore(g)} className="grid-line" />
            <text x={padL - 6} y={yScore(g) + 4} textAnchor="end" className="axis-text">{g}</text>
          </g>
        ))}
        {points.map((p, i) => {
          const yv = yBar(p.vulnerable);
          const yl = yBar(p.vulnerable + p.likely);
          return (
            <g key={p.id}>
              <rect x={x(i) - barW / 2} y={yv} width={barW} height={Math.max(0, base - yv)} className="tone-fill-crit trend-bar">
                <title>{`${p.date}: ${p.vulnerable} confirmadas`}</title>
              </rect>
              <rect x={x(i) - barW / 2} y={yl} width={barW} height={Math.max(0, yv - yl)} className="tone-fill-high trend-bar">
                <title>{`${p.date}: ${p.likely} prováveis`}</title>
              </rect>
              <text x={x(i)} y={H - 8} textAnchor="middle" className="axis-text">{p.date}</text>
            </g>
          );
        })}
        <path d={line} className="trend-line" fill="none" />
        {points.map((p, i) => (
          <circle key={p.id} cx={x(i)} cy={yScore(p.score)} r="3.5" className="trend-dot">
            <title>{`${p.date}: score ${p.score}`}</title>
          </circle>
        ))}
      </svg>
      <ul className="legend">
        <li><i className="dot line" aria-hidden="true" /> Score (0–100)</li>
        <li><i className="dot tone-bg-crit" aria-hidden="true" /> Vulnerabilidades confirmadas</li>
        <li><i className="dot tone-bg-high" aria-hidden="true" /> Prováveis</li>
      </ul>
      <details className="chart-table">
        <summary>Ver os números em tabela</summary>
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Score e vulnerabilidades por execução</caption>
            <thead>
              <tr><th scope="col">Execução</th><th scope="col">Score</th><th scope="col">Confirmadas</th><th scope="col">Prováveis</th><th scope="col">Cobertura</th></tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.id}>
                  <td>{p.date}</td><td>{p.score}</td><td>{p.vulnerable}</td><td>{p.likely}</td>
                  <td>{p.coveragePct == null ? "—" : `${p.coveragePct}%`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

/** Medidor de cobertura (verificações executadas ÷ planejadas). */
export function CoverageMeter({ pct, executed, planned }: { pct: number; executed: number; planned: number }) {
  return (
    <div className="coverage" role="img" aria-label={`Cobertura: ${executed} de ${planned} verificações executadas (${pct}%)`}>
      <div className="coverage-track">
        <div className="coverage-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="coverage-text">
        <b>{pct}%</b> <span>{executed} de {planned} verificações executadas</span>
      </div>
    </div>
  );
}
