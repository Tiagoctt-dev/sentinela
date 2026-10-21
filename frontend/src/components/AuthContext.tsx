import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api, AuthUser, clearToken, getToken, setToken } from "../api/client";
import LoginPage from "../pages/Login";

interface AuthApi {
  user: AuthUser | null;
  isAdmin: boolean;
  canWrite: boolean;
  logout: () => void;
}

const AuthCtx = createContext<AuthApi | null>(null);

type Phase = "loading" | "setup" | "login" | "ready" | "error";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [error, setError] = useState("");

  const bootstrap = useCallback(async () => {
    setPhase("loading");
    try {
      const status = await api.authStatus();
      if (!status.authRequired) {
        setUser({ id: "local", email: "local", name: "Modo local (sem login)", role: "admin" });
        return setPhase("ready");
      }
      if (!status.hasUsers) return setPhase("setup");
      if (!getToken()) return setPhase("login");
      try {
        setUser(await api.me());
        setPhase("ready");
      } catch {
        clearToken();
        setPhase("login");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Não foi possível falar com o servidor.");
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    bootstrap();
    const onExpired = () => {
      setUser(null);
      setPhase("login");
    };
    window.addEventListener("sentinela:unauthorized", onExpired);
    return () => window.removeEventListener("sentinela:unauthorized", onExpired);
  }, [bootstrap]);

  const logout = () => {
    clearToken();
    setUser(null);
    setPhase("login");
  };

  if (phase === "loading") return <p className="muted" style={{ padding: 32 }}>Carregando…</p>;
  if (phase === "error")
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <h1>Sem conexão</h1>
          <p className="muted">{error}</p>
          <button onClick={bootstrap}>Tentar de novo</button>
        </div>
      </div>
    );
  if (phase === "setup" || phase === "login")
    return (
      <LoginPage
        mode={phase}
        onAuthenticated={(token, u) => {
          setToken(token);
          setUser(u);
          setPhase("ready");
        }}
      />
    );

  return (
    <AuthCtx.Provider value={{ user, isAdmin: user?.role === "admin", canWrite: user?.role !== "viewer", logout }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth(): AuthApi {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth precisa estar dentro de <AuthProvider>");
  return ctx;
}
