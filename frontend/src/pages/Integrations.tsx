import { useEffect, useState } from "react";
import { api, GithubIntegration, SlackIntegration, Webhook } from "../api/client";
import AccordionSection from "../components/AccordionSection";
import Button from "../components/ui/Button";
import { Field, FormActions, FormGrid } from "../components/ui/Form";
import ConfirmDialog from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/ToastContext";

type DeleteTarget = { kind: "webhook" | "github" | "slack"; id: string; label: string } | null;

export default function IntegrationsPage() {
  const toast = useToast();
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [formOpen, setFormOpen] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);

  const [githubIntegrations, setGithubIntegrations] = useState<GithubIntegration[]>([]);
  const [githubFormOpen, setGithubFormOpen] = useState(false);
  const [githubRepo, setGithubRepo] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [githubSaving, setGithubSaving] = useState(false);
  const [githubTestingId, setGithubTestingId] = useState<string | null>(null);

  const [slackIntegrations, setSlackIntegrations] = useState<SlackIntegration[]>([]);
  const [slackFormOpen, setSlackFormOpen] = useState(false);
  const [slackName, setSlackName] = useState("");
  const [slackUrl, setSlackUrl] = useState("");
  const [slackSaving, setSlackSaving] = useState(false);
  const [slackTestingId, setSlackTestingId] = useState<string | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    api.listWebhooks().then(setWebhooks).catch((e) => toast.error(e));
    api.listGithub().then(setGithubIntegrations).catch((e) => toast.error(e));
    api.listSlack().then(setSlackIntegrations).catch((e) => toast.error(e));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const created = await api.createWebhook({ name, url });
      setWebhooks((prev) => [...prev, created]);
      setName("");
      setUrl("");
      setFormOpen(false);
    } catch (err) {
      toast.error(err);
    } finally {
      setSaving(false);
    }
  }

  async function toggle(w: Webhook) {
    try {
      const updated = await api.updateWebhook(w.id, { enabled: !w.enabled });
      setWebhooks((prev) => prev.map((x) => (x.id === w.id ? updated : x)));
    } catch (err) {
      toast.error(err);
    }
  }

  async function test(w: Webhook) {
    setTestingId(w.id);
    try {
      const updated = await api.testWebhook(w.id);
      setWebhooks((prev) => prev.map((x) => (x.id === w.id ? updated : x)));
      toast.success(`Webhook "${w.name}" testado.`);
    } catch (err) {
      toast.error(err);
    } finally {
      setTestingId(null);
    }
  }

  async function submitGithub(e: React.FormEvent) {
    e.preventDefault();
    setGithubSaving(true);
    try {
      const created = await api.createGithub({ repo: githubRepo, token: githubToken });
      setGithubIntegrations((prev) => [...prev, created]);
      setGithubRepo("");
      setGithubToken("");
      setGithubFormOpen(false);
    } catch (err) {
      toast.error(err);
    } finally {
      setGithubSaving(false);
    }
  }

  async function toggleGithub(g: GithubIntegration) {
    try {
      const updated = await api.updateGithub(g.id, { enabled: !g.enabled });
      setGithubIntegrations((prev) => prev.map((x) => (x.id === g.id ? updated : x)));
    } catch (err) {
      toast.error(err);
    }
  }

  async function testGithub(g: GithubIntegration) {
    setGithubTestingId(g.id);
    try {
      const updated = await api.testGithub(g.id);
      setGithubIntegrations((prev) => prev.map((x) => (x.id === g.id ? updated : x)));
      toast.success(`Integração "${g.repo}" testada.`);
    } catch (err) {
      toast.error(err);
    } finally {
      setGithubTestingId(null);
    }
  }

  async function submitSlack(e: React.FormEvent) {
    e.preventDefault();
    setSlackSaving(true);
    try {
      const created = await api.createSlack({ name: slackName, webhookUrl: slackUrl });
      setSlackIntegrations((prev) => [...prev, created]);
      setSlackName("");
      setSlackUrl("");
      setSlackFormOpen(false);
    } catch (err) {
      toast.error(err);
    } finally {
      setSlackSaving(false);
    }
  }

  async function toggleSlack(s: SlackIntegration) {
    try {
      const updated = await api.updateSlack(s.id, { enabled: !s.enabled });
      setSlackIntegrations((prev) => prev.map((x) => (x.id === s.id ? updated : x)));
    } catch (err) {
      toast.error(err);
    }
  }

  async function testSlack(s: SlackIntegration) {
    setSlackTestingId(s.id);
    try {
      const updated = await api.testSlack(s.id);
      setSlackIntegrations((prev) => prev.map((x) => (x.id === s.id ? updated : x)));
      toast.success(`Integração "${s.name}" testada.`);
    } catch (err) {
      toast.error(err);
    } finally {
      setSlackTestingId(null);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      if (deleteTarget.kind === "webhook") {
        await api.deleteWebhook(deleteTarget.id);
        setWebhooks((prev) => prev.filter((x) => x.id !== deleteTarget.id));
      } else if (deleteTarget.kind === "github") {
        await api.deleteGithub(deleteTarget.id);
        setGithubIntegrations((prev) => prev.filter((x) => x.id !== deleteTarget.id));
      } else {
        await api.deleteSlack(deleteTarget.id);
        setSlackIntegrations((prev) => prev.filter((x) => x.id !== deleteTarget.id));
      }
      setDeleteTarget(null);
    } catch (err) {
      toast.error(err);
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Integrações</h1>
          <div className="eyebrow">Conecte o Sentinela ao resto do seu fluxo — cada card explica exatamente quando dispara.</div>
        </div>
      </div>

      <div className="integration-card">
        <div className="integration-card-head">
          <div>
            <h3>Webhook genérico</h3>
            <p>Dispara em <b>todo scan concluído</b>, sem filtro de resultado — mesmo scans 100% conformes.</p>
          </div>
          <Button onClick={() => setFormOpen((v) => !v)}>+ Adicionar</Button>
        </div>

        <AccordionSection title="Como funciona">
          <p>
            Logo após cada scan terminar, o Sentinela envia um <code>POST</code> para a URL cadastrada, com o corpo:
          </p>
          <pre>{`{
  "event": "scan.completed",
  "scan": {
    "id": "...", "targetName": "...", "mode": "...",
    "overall": 50, "verdict": "Não conforme",
    "totals": { "PASS": 5, "FAIL": 5, "WARN": 4, "SKIP": 1 },
    "policy": { "passed": false, "violations": ["D-AUTHZ-01", "D-BOLA-01"] },
    "scanUrl": "http://localhost:5173/scans/...",
    "topFindings": [{
      "id": "D-AUTHZ-01", "severity": "CRITICAL", "owasp": "API1:2023",
      "title": "Acesso não autenticado negado em /users/v1/_debug",
      "evidence": "GET http://.../users/v1/_debug → HTTP 200 …",
      "recommendation": "...", "url": "http://localhost:5173/achados/..."
    }]
  }
}`}</pre>
          <p>
            <code>topFindings</code> traz até 10 falhas críticas/altas, cada uma com a requisição que provou o problema
            e o link para o achado. Use pra alimentar um pipeline próprio, um dashboard ou automações.
          </p>
          <p>
            Use o botão <b>Testar</b> para receber um evento <code>webhook.test</code> agora, sem precisar rodar um scan.
          </p>
        </AccordionSection>

        {formOpen && (
          <form onSubmit={submit} className="form form-panel">
            <FormGrid>
              <Field label="Nome" hint="Só para você identificar.">
                <input placeholder="Ex.: Painel de segurança" value={name} onChange={(e) => setName(e.target.value)} required />
              </Field>
              <Field label="URL que recebe os eventos" hint="É o endereço de quem recebe — não o sistema que você está testando.">
                <input placeholder="https://sua-url.com/webhook" value={url} onChange={(e) => setUrl(e.target.value)} required type="url" />
              </Field>
            </FormGrid>
            <FormActions>
              <Button type="button" variant="ghost" onClick={() => setFormOpen(false)}>Cancelar</Button>
              <Button type="submit" loading={saving} loadingLabel="Salvando…">Salvar</Button>
            </FormActions>
          </form>
        )}

        {webhooks.length > 0 && (
          <div style={{ display: "grid", gap: 8, marginTop: 14 }}>
            {webhooks.map((w) => (
              <div key={w.id} className="target-card" style={{ padding: "10px 14px" }}>
                <div className="target-main">
                  <div className="target-title" style={{ fontSize: 13.5 }}>
                    {w.name}
                    <span className={`pill ${w.enabled ? "pill-ok" : "pill-na"}`}>{w.enabled ? "ativo" : "pausado"}</span>
                  </div>
                  <div className="target-url mono">{w.url}</div>
                  {w.lastStatus && (
                    <div className="muted small">
                      último disparo: {w.lastStatus}
                      {w.lastTriggeredAt && ` · ${new Date(w.lastTriggeredAt).toLocaleString("pt-BR")}`}
                    </div>
                  )}
                </div>
                <div className="target-actions">
                  <Button variant="ghost" size="sm" onClick={() => test(w)} loading={testingId === w.id} loadingLabel="Testando…">
                    Testar
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => toggle(w)}>
                    {w.enabled ? "Pausar" : "Ativar"}
                  </Button>
                  <Button variant="ghost" size="sm" className="danger" onClick={() => setDeleteTarget({ kind: "webhook", id: w.id, label: w.name })}>
                    Excluir
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="integration-card">
        <div className="integration-card-head">
          <div>
            <h3>GitHub Issues</h3>
            <p>Cria <b>uma issue para cada achado crítico</b> (severidade CRÍTICA + status FALHA) — não uma issue por scan. Sem críticos, nada é criado.</p>
          </div>
          <Button onClick={() => setGithubFormOpen((v) => !v)}>+ Adicionar</Button>
        </div>

        <AccordionSection title="Como funciona">
          <p>
            Cada issue criada inclui alvo, categoria, severidade, tag OWASP, detalhe, evidência e recomendação — tudo
            que aparece na tela de achados — e recebe as labels <code>sentinela</code> e a severidade em minúsculo
            (ex.: <code>critical</code>).
          </p>
          <p>
            Gere um <b>Personal Access Token</b> (escopo <code>repo</code>) em github.com → Settings → Developer
            settings → Personal access tokens, e informe junto com o repositório de destino (<code>owner/repo</code>).
          </p>
        </AccordionSection>

        {githubFormOpen && (
          <form onSubmit={submitGithub} className="form form-panel">
            <FormGrid>
              <Field label="Repositório" hint="No formato dono/repositorio.">
                <input placeholder="owner/repo" value={githubRepo} onChange={(e) => setGithubRepo(e.target.value)} required />
              </Field>
              <Field label="Personal Access Token" hint="Escopo repo. Fica criptografado no servidor.">
                <input placeholder="ghp_…" value={githubToken} onChange={(e) => setGithubToken(e.target.value)} required type="password" autoComplete="off" />
              </Field>
            </FormGrid>
            <FormActions>
              <Button type="button" variant="ghost" onClick={() => setGithubFormOpen(false)}>Cancelar</Button>
              <Button type="submit" loading={githubSaving} loadingLabel="Salvando…">Salvar</Button>
            </FormActions>
          </form>
        )}

        {githubIntegrations.length > 0 && (
          <div style={{ display: "grid", gap: 8, marginTop: 14 }}>
            {githubIntegrations.map((g) => (
              <div key={g.id} className="target-card" style={{ padding: "10px 14px" }}>
                <div className="target-main">
                  <div className="target-title" style={{ fontSize: 13.5 }}>
                    {g.repo}
                    <span className={`pill ${g.enabled ? "pill-ok" : "pill-na"}`}>{g.enabled ? "ativo" : "pausado"}</span>
                  </div>
                  <div className="target-url mono">token {g.tokenMasked}</div>
                  {g.lastStatus && (
                    <div className="muted small">
                      última checagem: {g.lastStatus}
                      {g.lastTriggeredAt && ` · ${new Date(g.lastTriggeredAt).toLocaleString("pt-BR")}`}
                    </div>
                  )}
                </div>
                <div className="target-actions">
                  <Button variant="ghost" size="sm" onClick={() => testGithub(g)} loading={githubTestingId === g.id} loadingLabel="Testando…">
                    Testar
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => toggleGithub(g)}>
                    {g.enabled ? "Pausar" : "Ativar"}
                  </Button>
                  <Button variant="ghost" size="sm" className="danger" onClick={() => setDeleteTarget({ kind: "github", id: g.id, label: g.repo })}>
                    Excluir
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="integration-card">
        <div className="integration-card-head">
          <div>
            <h3>Slack</h3>
            <p>Alerta num canal <b>só quando o scan não sai "Conforme"</b> — silencioso em scans totalmente conformes.</p>
          </div>
          <Button onClick={() => setSlackFormOpen((v) => !v)}>+ Adicionar</Button>
        </div>

        <AccordionSection title="Como funciona">
          <p>Mensagem enviada quando o veredito é “Parcialmente conforme” ou “Não conforme”:</p>
          <pre>{`🚨 Sentinela — scan de <projeto> voltou <veredito> (score <n>/100).
• CRITICAL <título do achado> — <requisição que provou a falha>
• HIGH ...   (até 5 achados)
Ver o scan completo → <link>`}</pre>
          <p>
            Crie um <b>Incoming Webhook</b> no Slack (api.slack.com/apps → seu app → Incoming Webhooks) e informe a
            URL gerada — a integração usa o mesmo mecanismo de Webhook genérico acima, só que com esse texto pronto
            para o Slack.
          </p>
        </AccordionSection>

        {slackFormOpen && (
          <form onSubmit={submitSlack} className="form form-panel">
            <FormGrid>
              <Field label="Nome" hint="Ex.: canal #seguranca.">
                <input placeholder="Canal de alertas" value={slackName} onChange={(e) => setSlackName(e.target.value)} required />
              </Field>
              <Field label="URL do Incoming Webhook" hint="Gerada no Slack, em api.slack.com/apps.">
                <input placeholder="https://hooks.slack.com/services/…" value={slackUrl} onChange={(e) => setSlackUrl(e.target.value)} required type="url" />
              </Field>
            </FormGrid>
            <FormActions>
              <Button type="button" variant="ghost" onClick={() => setSlackFormOpen(false)}>Cancelar</Button>
              <Button type="submit" loading={slackSaving} loadingLabel="Salvando…">Salvar</Button>
            </FormActions>
          </form>
        )}

        {slackIntegrations.length > 0 && (
          <div style={{ display: "grid", gap: 8, marginTop: 14 }}>
            {slackIntegrations.map((s) => (
              <div key={s.id} className="target-card" style={{ padding: "10px 14px" }}>
                <div className="target-main">
                  <div className="target-title" style={{ fontSize: 13.5 }}>
                    {s.name}
                    <span className={`pill ${s.enabled ? "pill-ok" : "pill-na"}`}>{s.enabled ? "ativo" : "pausado"}</span>
                  </div>
                  <div className="target-url mono">{s.webhookUrl}</div>
                  {s.lastStatus && (
                    <div className="muted small">
                      último disparo: {s.lastStatus}
                      {s.lastTriggeredAt && ` · ${new Date(s.lastTriggeredAt).toLocaleString("pt-BR")}`}
                    </div>
                  )}
                </div>
                <div className="target-actions">
                  <Button variant="ghost" size="sm" onClick={() => testSlack(s)} loading={slackTestingId === s.id} loadingLabel="Testando…">
                    Testar
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => toggleSlack(s)}>
                    {s.enabled ? "Pausar" : "Ativar"}
                  </Button>
                  <Button variant="ghost" size="sm" className="danger" onClick={() => setDeleteTarget({ kind: "slack", id: s.id, label: s.name })}>
                    Excluir
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={!!deleteTarget}
        title="Excluir integração"
        description={`Excluir "${deleteTarget?.label}"? Essa ação não pode ser desfeita.`}
        confirmLabel="Excluir"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
