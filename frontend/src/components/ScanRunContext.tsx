import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { ScanDetail } from "../api/client";
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
  useEffect(() => {
    const id = setInterval(() => setElapsed(Date.now() - startedAt), 250);
    return () => clearInterval(id);
  }, [startedAt]);

  return (
    <div className="scan-run-banner">
      <Spinner />
      <span>
        Scan em andamento para <b>{label}</b>
      </span>
      <span className="elapsed">{(elapsed / 1000).toFixed(0)}s</span>
    </div>
  );
}

export function useScanRun(): ScanRunApi {
  const ctx = useContext(ScanRunCtx);
  if (!ctx) throw new Error("useScanRun precisa estar dentro de <ScanRunProvider>");
  return ctx;
}
