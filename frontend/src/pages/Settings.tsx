import { FormEvent, useEffect, useState } from "react";
import { AiTestResult, api, RetentionStatus } from "../api/client";
import { useAuth } from "../components/AuthContext";
import Button from "../components/ui/Button";
import { Field, FormActions, FormGrid } from "../components/ui/Form";
import { useToast } from "../components/ui/ToastContext";

function MyAccount() {
  const toast = useToast();
  const { user, replaceSession } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [saving, setSaving] = useState(false);
  const mismatch = again.length > 0 && next !== again;

  if (!user || user.id === "local") return null;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (next !== again) return;
    setSaving(true);
    try {
      const res = await api.changePassword({ currentPassword: current, newPassword: next });
      replaceSession(res.token, res.user);
      setCurrent("");
      setNext("");
      setAgain("");
      toast.success("Senha alterada. As outras sessões abertas com a senha antiga foram encerradas.");
    } catch (err) {
      toast.error(err);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="integration-card">
      <div className="integration-card-head">
        <div>
          <h3>Minha conta</h3>
          <p>
            {user.name} · {user.email}. Ao trocar a senha, as outras sessões abertas com a senha antiga são encerradas.
          </p>
        </div>
      </div>
      <form onSubmit={submit}>
        <FormGrid>
          <Field label="Senha atual">
            <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </Field>
          <Field label="Nova senha" hint="Mínimo de 10 caracteres.">
            <input type="password" autoComplete="new-password" minLength={10} value={next} onChange={(e) => setNext(e.target.value)} required />
          </Field>
          <Field label="Repita a nova senha" hint={mismatch ? "As senhas não são iguais." : undefined}>
            <input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} aria-invalid={mismatch} required />
          </Field>
        </FormGrid>
        <FormActions>
          <Button type="submit" loading={saving} loadingLabel="Salvando…" disabled={mismatch || !current || !next}>
            Trocar senha
          </Button>
        </FormActions>
      </form>
    </div>
  );
}

function Retention() {
  const toast = useToast();
  const { isAdmin } = useAuth();
  const [status, setStatus] = useState<RetentionStatus | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (isAdmin) api.getRetention().then(setStatus).catch(() => setStatus(null));
  }, [isAdmin]);

  if (!isAdmin || !status) return null;
  const { policy, stored } = status;
  const days = (n: number) => (n ? `${n} dias` : "nunca apagar");

  async function run() {
    setRunning(true);
    try {
      const res = await api.runRetention();
      const removed = Object.values(res.removed).reduce((a, b) => a + b, 0);
      toast.success(`Limpeza concluída: ${removed} registro(s) removido(s), ${res.expiredRiskAcceptances} aceite(s) de risco vencido(s).`);
      setStatus(await api.getRetention());
    } catch (e) {
      toast.error(e);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="integration-card">
      <div className="integration-card-head">
        <div>
          <h3>Retenção de dados</h3>
          <p>{policy.note}</p>
        </div>
        <Button variant="ghost" onClick={run} loading={running} loadingLabel="Limpando…">
          Aplicar agora
        </Button>
      </div>
      <dl className="kv-list">
        <div><dt>Trilha de auditoria</dt><dd>{days(policy.auditDays)} · {stored.auditEntries} registro(s)</dd></div>
        <div><dt>Scans</dt><dd>{days(policy.scanDays)} · {stored.scans} scan(s), {stored.findings} resultado(s)</dd></div>
      </dl>
      <p className="muted small">A limpeza roda sozinha uma vez por dia. Os valores vêm de SENTINELA_AUDIT_RETENTION_DAYS e SENTINELA_SCAN_RETENTION_DAYS no servidor.</p>
    </div>
  );
}

export default function SettingsPage() {
  const toast = useToast();
  const [results, setResults] = useState<AiTestResult[] | null>(null);
  const [testing, setTesting] = useState(false);

  async function testAi() {
    setTesting(true);
    try {
      setResults(await api.testAi());
    } catch (e) {
      toast.error(e);
    } finally {
      setTesting(false);
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Configurações</h1>
          <div className="eyebrow">Chaves e variáveis ficam no arquivo backend/.env — nunca no navegador.</div>
        </div>
      </div>

      <MyAccount />
      <Retention />

      <div className="integration-card">
        <div className="integration-card-head">
          <div>
            <h3>Camada de IA (Gemini e Groq)</h3>
            <p>
              A IA escreve as recomendações de correção de cada achado. Se ela falhar, o scan continua normalmente e usa
              as recomendações estáticas.
            </p>
          </div>
          <Button onClick={testAi} loading={testing} loadingLabel="Testando…">
            Testar conexão com a IA
          </Button>
        </div>

        {results && (
          <div className="ai-test-list">
            {results.map((r) => (
              <div key={r.provider} className="ai-test-row">
                <span className={`pill ${r.ok ? "pill-ok" : r.configured ? "pill-fail" : "pill-na"}`}>
                  {r.ok ? "funcionando" : r.configured ? "com erro" : "não configurado"}
                </span>
                <div>
                  <b>{r.provider}</b>
                  {r.keyHint && <span className="muted small mono"> · chave {r.keyHint}</span>}
                  <div className="muted small">{r.message}</div>
                  {!r.ok && r.transient && (
                    <div className="small text-warn mt-1">
                      Erro temporário do provedor (sobrecarga/limite) — a chave está correta. Tente de novo em instantes;
                      o Sentinela já repete e troca de modelo automaticamente.
                    </div>
                  )}
                  {!r.ok && r.configured && !r.transient && (
                    <div className="small text-crit mt-1">
                      Verifique a chave em backend/.env e reinicie o backend.
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <details className="accordion">
          <summary>Como configurar</summary>
          <div className="accordion-body">
            <p>
              Crie <code>backend/.env</code> (modelo em <code>.env.example</code>) com <code>GEMINI_API_KEY</code> e/ou{" "}
              <code>GROQ_API_KEY</code>. Depois de alterar, <b>reinicie o backend</b> — o arquivo só é lido na inicialização.
            </p>
            <p>
              Gemini: gere a chave em aistudio.google.com/apikey. Groq: console.groq.com/keys. O formato da chave não
              importa — use o botão acima pra confirmar que ela funciona.
            </p>
            <p>
              Erros “503 / sobrecarga” vêm do Google, não da sua chave: trocar de conta não resolve. O Sentinela tenta de
              novo e cai para outros modelos sozinho.
            </p>
          </div>
        </details>
      </div>
    </div>
  );
}
