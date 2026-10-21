import { createContext, ReactNode, useCallback, useContext, useRef, useState } from "react";
import { ApiError } from "../../api/client";

type ToastKind = "error" | "success";
interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastApi {
  error: (err: unknown) => void;
  success: (message: string) => void;
}

const ToastCtx = createContext<ToastApi | null>(null);

export function messageFromError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Erro inesperado.";
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = ++nextId.current;
      setItems((prev) => [...prev, { id, kind, message }]);
      setTimeout(() => dismiss(id), 6000);
    },
    [dismiss]
  );

  const api: ToastApi = {
    error: (err) => push("error", messageFromError(err)),
    success: (message) => push("success", message),
  };

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="toast-stack">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            <span className="msg">{t.message}</span>
            <button className="close" onClick={() => dismiss(t.id)} aria-label="Fechar">
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error("useToast precisa estar dentro de <ToastProvider>");
  return ctx;
}
