import { DependencyList, useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  error: string;
  loading: boolean;
  reload: () => void;
  setData: (next: T | ((prev: T | null) => T | null)) => void;
}

/** Carrega dados com estados explícitos de carregamento/erro e descarta respostas de requisições antigas. */
export function useAsync<T>(load: () => Promise<T>, deps: DependencyList): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const ticket = useRef(0);

  const run = useCallback(() => {
    const mine = ++ticket.current;
    setLoading(true);
    setError("");
    load()
      .then((result) => {
        if (mine === ticket.current) setData(result);
      })
      .catch((err: unknown) => {
        if (mine === ticket.current) setError(err instanceof Error ? err.message : "Erro inesperado.");
      })
      .finally(() => {
        if (mine === ticket.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    run();
  }, [run]);

  return { data, error, loading, reload: run, setData };
}
