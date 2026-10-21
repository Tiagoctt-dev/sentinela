type Tone = "crit" | "high" | "med" | "low" | "ok" | "na";

const toneClass: Record<Tone, string> = {
  crit: "crit", high: "high", med: "med", low: "low", ok: "ok", na: "info",
};

export function SevBadge({ severity }: { severity: string }) {
  const cls = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" }[severity] || "info";
  return <span className={`sev ${cls}`}>{severity}</span>;
}

export function StatusPill({ tone, children }: { tone: "ok" | "warn" | "fail" | "na"; children: React.ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export default function Badge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return <span className={`sev ${toneClass[tone]}`}>{children}</span>;
}
