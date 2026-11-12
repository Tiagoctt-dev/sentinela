import type { Confidence, FindingState, RouteState, Severity } from "../../api/client";
import { CONFIDENCE_LABEL, ROUTE_STATE_META, SEVERITY_LABEL, stateMeta } from "../../lib/results";

const SEV_CLASS: Record<Severity, string> = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" };

/** Severidade sempre com rótulo textual — a cor reforça, não substitui. */
export function SevBadge({ severity }: { severity: Severity }) {
  return <span className={`sev ${SEV_CLASS[severity] ?? "info"}`}>{SEVERITY_LABEL[severity] ?? severity}</span>;
}

export function StateBadge({ state, short = false }: { state: FindingState | string; short?: boolean }) {
  const m = stateMeta(state);
  return (
    <span className={`state-badge tone-${m.tone}`} title={m.help}>
      <span aria-hidden="true">{m.icon}</span> {short ? m.short : m.label}
    </span>
  );
}

export function RouteStateBadge({ state }: { state: RouteState }) {
  const m = ROUTE_STATE_META[state];
  return (
    <span className={`state-badge tone-${m.tone}`} title={m.help}>
      <span aria-hidden="true">{m.icon}</span> {m.short}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  if (confidence === "none") return <span className="muted">—</span>;
  return <span className={`conf-badge conf-${confidence}`}>{CONFIDENCE_LABEL[confidence]}</span>;
}

export function StatusPill({ tone, children }: { tone: "ok" | "warn" | "fail" | "na"; children: React.ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}
