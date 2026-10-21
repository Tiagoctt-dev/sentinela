import { useEffect, useState } from "react";
import Spinner from "./Spinner";

// Rótulo heurístico por faixa de tempo decorrido — NÃO reflete fases reais
// do backend (o scan roda numa request só, sem relato de progresso). É só
// uma pista melhor do que "Rodando…" parado por 20s+.
function heuristicLabel(elapsedMs: number): string {
  if (elapsedMs < 3000) return "Rodando…";
  if (elapsedMs < 10000) return "Analisando código e endpoints…";
  return "Aguardando IA…";
}

export function useElapsed(active: boolean) {
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    if (!active) {
      setElapsedMs(0);
      return;
    }
    const start = Date.now();
    const id = setInterval(() => setElapsedMs(Date.now() - start), 250);
    return () => clearInterval(id);
  }, [active]);

  return elapsedMs;
}

export default function ProgressIndicator({ elapsedMs, label }: { elapsedMs: number; label?: string }) {
  const seconds = (elapsedMs / 1000).toFixed(0);
  return (
    <span className="progress-indicator">
      <Spinner />
      <span>{label || heuristicLabel(elapsedMs)}</span>
      <span className="elapsed">{seconds}s</span>
    </span>
  );
}
