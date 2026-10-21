import { ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Finding } from "../api/client";

const passIcon = (s: string) => (s === "PASS" ? "✔" : s === "FAIL" ? "✘" : s === "WARN" ? "▲" : "–");
const stClass = (s: string) => ({ PASS: "ok", FAIL: "fail", WARN: "warn", SKIP: "skip" }[s] || "skip");
const sevClass = (s: string) => ({ CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" }[s] || "info");
const resLabel = (r: string) => ({ open: "aberto", resolved: "resolvido", risk_accepted: "risco aceito" }[r] || r);

export default function FindingCard({
  f,
  linkable = true,
  footer,
}: {
  f: Finding;
  linkable?: boolean;
  footer?: ReactNode;
}) {
  const navigate = useNavigate();
  const clickable = linkable && f.status !== "PASS" && f.status !== "SKIP";

  return (
    <div
      className={`finding ${stClass(f.status)} ${clickable ? "clickable" : ""}`}
      onClick={clickable ? () => navigate(`/achados/${f.rowId}`) : undefined}
    >
      <div className="fi-icon">{passIcon(f.status)}</div>
      <div className="fi-body">
        <div className="fi-top">
          <span className="fi-title">{f.title}</span>
          <span className={`sev ${sevClass(f.severity)}`}>{f.severity}</span>
          {f.owasp && <span className="owasp mono">{f.owasp}</span>}
          <span className="cat mono">{f.category}</span>
          {clickable && <span className={`res-badge res-${f.resolution}`}>{resLabel(f.resolution)}</span>}
          <span className="fid mono">{f.id}</span>
        </div>
        {f.detail && <p className="fi-detail">{f.detail}</p>}
        {f.aiRec ? (
          Object.entries(f.aiRec).map(([key, rec]) => (
            <p className="fi-rec" key={key}>
              <span className="ai-badge">{rec.provider}</span> {rec.acao}
              {rec.prioridade && <span className={`prio ${rec.prioridade}`}> prioridade {rec.prioridade}</span>}
            </p>
          ))
        ) : (
          f.status !== "PASS" && f.recommendation && <p className="fi-rec">→ {f.recommendation}</p>
        )}
        {footer}
      </div>
    </div>
  );
}
