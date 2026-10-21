const DASH = 314.16;

export default function Gauge({ score, verdict }: { score: number; verdict: string }) {
  const offset = DASH - (DASH * score) / 100;
  const cls = score >= 85 ? "ok" : score >= 60 ? "warn" : "fail";

  return (
    <div className="gauge">
      <svg viewBox="0 0 120 120" role="img" aria-label={`Score de segurança: ${score} de 100`}>
        <circle cx="60" cy="60" r="50" fill="none" className="track" strokeWidth="12" />
        <circle
          cx="60" cy="60" r="50" fill="none" strokeWidth="12" strokeLinecap="round"
          className={`fill-${cls}`}
          strokeDasharray={DASH.toFixed(2)}
          strokeDashoffset={offset.toFixed(2)}
          transform="rotate(-90 60 60)"
        />
        <text className="gval" x="60" y="60" textAnchor="middle" dominantBaseline="central">{score}</text>
        <text className="glbl" x="60" y="88" textAnchor="middle">DE 100</text>
      </svg>
      <div className={`verdict verdict-${cls}`}>{verdict}</div>
    </div>
  );
}
