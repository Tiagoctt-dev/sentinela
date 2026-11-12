import { Finding } from "../api/client";

const ORDER: { key: Finding["severity"]; label: string; cls: string }[] = [
  { key: "CRITICAL", label: "Crítico", cls: "crit" },
  { key: "HIGH", label: "Alto", cls: "high" },
  { key: "MEDIUM", label: "Médio", cls: "med" },
  { key: "LOW", label: "Baixo", cls: "low" },
  { key: "INFO", label: "Info", cls: "info" },
];

export default function SeverityBar({ findings }: { findings: Pick<Finding, "severity">[] }) {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach((f) => {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  });
  const total = findings.length;
  if (!total) return null;
  const present = ORDER.filter((o) => counts[o.key] > 0);

  return (
    <div className="sev-bar">
      <div className="sev-bar-track">
        {present.map((o) => (
          <div
            key={o.key}
            className={`sev-bar-seg sev-${o.cls}`}
            style={{ width: `${(counts[o.key] / total) * 100}%` }}
            title={`${o.label}: ${counts[o.key]}`}
          />
        ))}
      </div>
      <div className="sev-bar-legend">
        {present.map((o) => (
          <span key={o.key} className={`sev-bar-item sev-${o.cls}`}>
            <i /> {o.label} <b>{counts[o.key]}</b>
          </span>
        ))}
      </div>
    </div>
  );
}
