import { useState } from "react";
import { api, AuthUser } from "../api/client";
import Button from "../components/ui/Button";
import { Field } from "../components/ui/Form";

interface Props {
  mode: "setup" | "login";
  onAuthenticated: (token: string, user: AuthUser) => void;
}

export default function LoginPage({ mode, onAuthenticated }: Props) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const setup = mode === "setup";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (setup && password !== confirm) return setError("As senhas não conferem.");
    setBusy(true);
    try {
      const res = setup ? await api.bootstrap({ name, email, password }) : await api.login({ email, password });
      onAuthenticated(res.token, res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro ao entrar.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <form className="auth-card form" onSubmit={submit}>
        <div className="auth-brand">
          <span className="hex">⬢</span>
          <span className="name">Sentinela</span>
        </div>
        <h1>{setup ? "Criar o administrador" : "Entrar"}</h1>
        <p className="muted small" style={{ margin: 0 }}>
          {setup
            ? "Primeiro acesso: crie a conta do administrador. Ela poderá cadastrar os demais usuários."
            : "Use o e-mail e a senha cadastrados pelo administrador."}
        </p>

        {setup && (
          <Field label="Nome">
            <input required value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
          </Field>
        )}
        <Field label="E-mail">
          <input required type="text" inputMode="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" autoFocus />
        </Field>
        <Field label="Senha" hint={setup ? "Mínimo de 10 caracteres." : undefined}>
          <input required type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={setup ? "new-password" : "current-password"} />
        </Field>
        {setup && (
          <Field label="Confirmar senha">
            <input required type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </Field>
        )}

        {error && <p className="error" role="alert" style={{ margin: 0 }}>{error}</p>}
        <Button type="submit" loading={busy} loadingLabel={setup ? "Criando…" : "Entrando…"}>
          {setup ? "Criar administrador" : "Entrar"}
        </Button>
      </form>
    </div>
  );
}
