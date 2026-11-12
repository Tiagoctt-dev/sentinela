import { ReactNode } from "react";
import Button from "./Button";
import Spinner from "./Spinner";

/** Padroniza carregamento, erro (com nova tentativa) e conteúdo. */
export default function AsyncView({
  loading, error, onRetry, hasData, children,
}: {
  loading: boolean;
  error: string;
  onRetry?: () => void;
  hasData: boolean;
  children: ReactNode;
}) {
  if (error && !hasData)
    return (
      <div className="async-error" role="alert">
        <p>{error}</p>
        {onRetry && (
          <Button variant="ghost" onClick={onRetry}>
            Tentar de novo
          </Button>
        )}
      </div>
    );
  if (loading && !hasData)
    return (
      <div className="async-loading" role="status" aria-label="Carregando">
        <div className="skeleton-stack" aria-hidden="true">
          <div className="skeleton sk-row" />
          <div className="skeleton sk-block" />
          <div className="skeleton sk-block short" />
        </div>
        <span className="sr-only"><Spinner /> Carregando…</span>
      </div>
    );
  return <>{children}</>;
}
