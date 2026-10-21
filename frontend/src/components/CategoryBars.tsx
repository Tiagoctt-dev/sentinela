import { CategoryScore } from "../api/client";

export default function CategoryBars({ categories }: { categories: CategoryScore[] }) {
  return (
    <div className="bars">
      {categories.map((cat) => {
        const n = cat.score;
        const cls = n == null ? "skip" : n >= 85 ? "ok" : n >= 60 ? "warn" : "fail";
        return (
          <div className="bar-row" key={cat.key}>
            <div className="bar-head">
              <span>{cat.label}</span>
              {n == null ? (
                <span className="na-label" title="Nenhuma verificação desta categoria foi aplicável neste scan (falta configuração ou o sistema não usa este recurso).">
                  não avaliado
                </span>
              ) : (
                <span className="pct">{n}</span>
              )}
            </div>
            <div className="track">
              <div className={`fill fill-${cls}`} style={{ width: `${n ?? 0}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
