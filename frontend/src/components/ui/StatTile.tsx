import { ReactNode } from "react";
import { Link } from "react-router-dom";

export default function StatTile({
  label, value, hint, tone, to,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "crit" | "ok" | "warn";
  /** Quando informado, o cartão inteiro é um link para a lista correspondente. */
  to?: string;
}) {
  const body = (
    <>
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${tone ?? ""}`}>{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </>
  );
  return to ? (
    <Link to={to} className="stat-tile stat-link" aria-label={`${label}: ${typeof value === "object" ? "" : value}. Abrir`}>
      {body}
    </Link>
  ) : (
    <div className="stat-tile">{body}</div>
  );
}
