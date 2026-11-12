import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api, ScanDetail } from "../api/client";
import Spinner from "./ui/Spinner";
import { useToast } from "./ui/ToastContext";

interface RunState {
  label: string;
  startedAt: number;
}

interface ScanRunApi {
  active: RunState | null;
  run: (label: string, fn: () => Promise<ScanDetail>) => Promise<ScanDetail>;
}

const ScanRunCtx = createContext<ScanRunApi | null>(null);

export function ScanRunProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<RunState | null>(null);
  const toast = useToast();

  const run = useCallback(
    async (label: string, fn: () => Promise<ScanDetail>) => {
      setActive({ label, startedAt: Date.now() });
      try {
        const result = await fn();
        toast.success(`Scan de "${label}" concluído — score ${result.overall}/100 (${result.verdict}).`);
        return result;
      } catch (err) {
        toast.error(err);
        throw err;
      } finally {
        setActive(null);
      }
    },
    [toast]
  );

  return (
    <ScanRunCtx.Provider value={{ active, run }}>
      {children}
      {active && <ScanRunBanner label={active.label} startedAt={active.startedAt} />}
    </ScanRunCtx.Provider>
  );
}

function ScanRunBanner({ label, startedAt }: { label: string; startedAt: number }) {
  const [elapsed, setElapsed] = useState(() => Date.now() - startedAt);
  const [step, setStep] = useState<{ label: string; done: number; total: number } | null>(null);
  useEffect(() => {
    const id = setInterval(() => setElapsed(Date.now() - startedAt), 250);
    return () => clearInterval(id);
  }, [startedAt]);
  useEffect(() => {
    let alive = true;
    const poll = () => api.scanProgress().then((r) => alive && setStep(r.running[0] ?? null)).catch(() => undefined);
    poll();
    const id = setInterval(poll, 1500);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="scan-run-banner" role="status">
      <Spinner />
      <div className="scan-run-text">
        <span>
          Scan em andamento: <b>{label}</b>
        </span>
        {step && (
          <>
            <span className="scan-run-step">{step.label} · etapa {Math.min(step.done + 1, step.total)} de {step.total}</span>
            <span className="scan-run-bar" aria-hidden="true"><i style={{ width: `${Math.round((step.done / step.total) * 100)}%` }} /></span>
          </>
        )}
      </div>
      <span className="elapsed">{(elapsed / 1000).toFixed(0)}s</span>
    </div>
  );
}

export function useScanRun(): ScanRunApi {
  const ctx = useContext(ScanRunCtx);
  if (!ctx) throw new Error("useScanRun precisa estar dentro de <ScanRunProvider>");
  return ctx;
}
