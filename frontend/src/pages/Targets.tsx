import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, Credential, Schedule, TargetInfo } from "../api/client";
import { useScanRun } from "../components/ScanRunContext";
import { useAuth } from "../components/AuthContext";
import Button from "../components/ui/Button";
import { Field, FormActions, FormGrid, FormSection } from "../components/ui/Form";
import MoreMenu from "../components/ui/MoreMenu";
import EmptyState from "../components/ui/EmptyState";
import Modal from "../components/ui/Modal";
import ProgressIndicator, { useElapsed } from "../components/ui/ProgressIndicator";
import ConfirmDialog from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/ToastContext";

const emptyForm = {
  name: "", baseUrl: "", description: "",
  loginPath: "", tokenField: "token", protectedProbe: "", registerPath: "",
  openapiUrl: "", wsdlUrl: "",
  protectedRoutes: "", bolaMethod: "PUT", bolaPath: "", bolaBody: "", bflaRoutes: "",
};
type FormState = typeof emptyForm;

function formFromTarget(t: TargetInfo): FormState {
  const c = t.config;
  return {
    name: c.name || "", baseUrl: c.baseUrl || "", description: c.description || "",
    loginPath: c.auth?.login || "", tokenField: c.auth?.tokenField || "token",
    protectedProbe: c.auth?.protectedProbe || "", registerPath: c.auth?.register || "",
    openapiUrl: c.openapiUrl || "", wsdlUrl: c.wsdlUrl || "",
    protectedRoutes: (c.endpoints?.protectedGet || []).join("\n"),
    bolaMethod: c.bola?.method || "PUT", bolaPath: c.bola?.path || "",
    bolaBody: c.bola?.body ? JSON.stringify(c.bola.body) : "",
    bflaRoutes: (c.bfla || []).map((r) => `${r.method} ${r.path}`).join("\n"),
  };
}

// Só envia as seções que o usuário preencheu — o backend ignora o resto.
function inputFromForm(f: FormState) {
  const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);
  const routes = lines(f.protectedRoutes);
  const bfla = lines(f.bflaRoutes).map((l) => {
    const [first, ...rest] = l.split(/\s+/);
    return rest.length ? { method: first.toUpperCase(), path: rest.join(" ") } : { method: "GET", path: first };
  });
  let bolaBody: unknown = undefined;
  if (f.bolaBody.trim()) bolaBody = JSON.parse(f.bolaBody);
  const hasAuth = f.loginPath.trim() || f.registerPath.trim();
  return {
    name: f.name, baseUrl: f.baseUrl, description: f.description,
    openapiUrl: f.openapiUrl.trim(), wsdlUrl: f.wsdlUrl.trim(),
    endpoints: { protectedGet: routes },
    auth: hasAuth
      ? {
          ...(f.loginPath.trim() && { login: f.loginPath.trim() }),
          ...(f.registerPath.trim() && { register: f.registerPath.trim() }),
          tokenField: f.tokenField.trim() || "token", scheme: "Bearer ",
          ...(f.protectedProbe.trim() && { protectedProbe: f.protectedProbe.trim() }),
        }
      : {},
    bola: f.bolaPath.trim() ? { method: f.bolaMethod, path: f.bolaPath.trim(), ...(bolaBody !== undefined && { body: bolaBody }) } : {},
    bfla,
  };
}

export default function TargetsPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const { isAdmin, canWrite } = useAuth();
  const { run, active } = useScanRun();
  const [targets, setTargets] = useState<TargetInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [schedTarget, setSchedTarget] = useState<TargetInfo | null>(null);
  const [schedule, setSchedule] = useState<Schedule | null>(null);
  const [credTarget, setCredTarget] = useState<TargetInfo | null>(null);
  const [creds, setCreds] = useState<Credential[]>([]);
  const [credForm, setCredForm] = useState({ label: "", role: "user", username: "", password: "", resourceId: "" });
  const [credSaving, setCredSaving] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TargetInfo | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [search, setSearch] = useState("");
  const [quickUrl, setQuickUrl] = useState("");
  const [quickRunning, setQuickRunning] = useState(false);
  const elapsed = useElapsed(runningId != null);
  const quickElapsed = useElapsed(quickRunning);

  useEffect(() => {
    api
      .listTargets()
      .then(setTargets)
      .catch((e) => toast.error(e))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function openCreate() {
    setForm(emptyForm);
    setEditingId(null);
    setFormOpen(true);
  }

  function openEdit(t: TargetInfo) {
    setForm(formFromTarget(t));
    setEditingId(t.id);
    setFormOpen(true);
  }

  async function submitForm(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      let input;
      try {
        input = inputFromForm(form);
      } catch {
        toast.error("O corpo do teste de BOLA não é um JSON válido — ex.: {\"email\": \"x@y.com\"}");
        setSaving(false);
        return;
      }
      if (editingId) {
        const updated = await api.updateTarget(editingId, input);
        setTargets((prev) => prev.map((t) => (t.id === editingId ? updated : t)));
      } else {
        const created = await api.createTarget(input);
        setTargets((prev) => [...prev, created]);
      }
      setFormOpen(false);
    } catch (err) {
      toast.error(err);
    } finally {
      setSaving(false);
    }
  }

  async function openSchedule(t: TargetInfo) {
    setSchedTarget(t);
    setSchedule(null);
    try {
      setSchedule(await api.getSchedule(t.id));
    } catch (e) {
      toast.error(e);
    }
  }

  async function changeSchedule(value: string) {
    if (!schedTarget) return;
    try {
      if (value === "0") {
        await api.clearSchedule(schedTarget.id);
        setSchedule(await api.getSchedule(schedTarget.id));
      } else {
        setSchedule(await api.setSchedule(schedTarget.id, Number(value)));
      }
    } catch (e) {
      toast.error(e);
    }
  }

  async function openCreds(t: TargetInfo) {
    setCredTarget(t);
    setCreds([]);
    setCredForm({ label: "", role: "user", username: "", password: "", resourceId: "" });
    try {
      setCreds(await api.listCredentials(t.id));
    } catch (e) {
      toast.error(e);
    }
  }

  async function addCred(e: React.FormEvent) {
    e.preventDefault();
    if (!credTarget) return;
    setCredSaving(true);
    try {
      const created = await api.createCredential(credTarget.id, { ...credForm, resourceId: credForm.resourceId || undefined });
      setCreds((prev) => [...prev, created]);
      setCredForm({ label: "", role: credForm.role, username: "", password: "", resourceId: "" });
    } catch (err) {
      toast.error(err);
    } finally {
      setCredSaving(false);
    }
  }

  async function removeCred(id: string) {
    if (!credTarget) return;
    try {
      await api.deleteCredential(credTarget.id, id);
      setCreds((prev) => prev.filter((c) => c.id !== id));
    } catch (err) {
      toast.error(err);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.deleteTarget(deleteTarget.id);
      setTargets((prev) => prev.filter((t) => t.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (err) {
      toast.error(err);
    } finally {
      setDeleting(false);
    }
  }

  async function runScan(t: TargetInfo) {
    setRunningId(t.id);
    try {
      const scan = await run(t.config.name || t.name, () => api.runScan({ targetId: t.id }));
      navigate(`/scans/${scan.id}`);
    } catch {
      // erro já mostrado via toast pelo ScanRunContext
    } finally {
      setRunningId(null);
    }
  }

  async function runQuickScan(e: React.FormEvent) {
    e.preventDefault();
    const url = quickUrl.trim();
    if (!url) return;
    setQuickRunning(true);
    try {
      const scan = await run(url, () => api.runScan({ url, static: false }));
      setQuickUrl("");
      navigate(`/scans/${scan.id}`);
    } catch {
      // erro já mostrado via toast pelo ScanRunContext
    } finally {
      setQuickRunning(false);
    }
  }

  const term = search.trim().toLowerCase();
  const matches = (t: TargetInfo) =>
    !term || `${t.config.name || t.name} ${t.config.baseUrl || ""} ${t.config.description || ""}`.toLowerCase().includes(term);

  const mine = targets.filter((t) => t.source === "custom" && matches(t));
  const examples = targets.filter((t) => t.source === "file" && matches(t));

  function renderCard(t: TargetInfo) {
    const isRunning = runningId === t.id;
    return (
      <div key={t.id} className="target-card">
        <div className="target-main">
          <div className="target-title">
            {t.config.name || t.name}
            <span className={`badge badge-${t.source}`}>{t.source === "file" ? "exemplo" : "meu projeto"}</span>
          </div>
          {t.config.description && <div className="target-desc">{t.config.description}</div>}
          <div className="target-url mono">{t.config.baseUrl}</div>
        </div>
        <div className="target-actions">
          {isRunning ? (
            <ProgressIndicator elapsedMs={elapsed} />
          ) : (
            <Button onClick={() => runScan(t)} disabled={!!active}>
              Rodar scan
            </Button>
          )}
          <Button variant="ghost" onClick={() => navigate(`/scans?targetId=${t.id}`)}>
            Histórico
          </Button>
          <MoreMenu
            items={[
              ...(canWrite ? [{ label: "Agendar scans", onClick: () => openSchedule(t) }] : []),
              ...(isAdmin ? [{ label: "Usuários de teste", onClick: () => openCreds(t) }] : []),
              ...(canWrite && t.source === "custom" ? [{ label: "Editar projeto", onClick: () => openEdit(t) }] : []),
              ...(canWrite && t.source === "custom" ? [{ label: "Excluir projeto", danger: true, onClick: () => setDeleteTarget(t) }] : []),
            ]}
          />
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Projetos</h1>
          <div className="eyebrow">Escolha um sistema e rode um scan. O resultado aparece em Scans; o que corrigir, em Achados.</div>
        </div>
        <Button onClick={openCreate}>+ Novo projeto</Button>
      </div>

      <form className="quick-scan" onSubmit={runQuickScan}>
        <div>
          <h3>Escanear uma URL</h3>
          <p>Teste externo de um sistema já publicado.</p>
        </div>
        <div className="quick-scan-row">
          <input
            type="url"
            required
            placeholder="https://api.seusistema.com"
            value={quickUrl}
            onChange={(e) => setQuickUrl(e.target.value)}
            disabled={quickRunning}
          />
          {quickRunning ? (
            <ProgressIndicator elapsedMs={quickElapsed} />
          ) : (
            <Button type="submit" disabled={!!active || !quickUrl.trim()}>
              Rodar scan
            </Button>
          )}
        </div>
      </form>

      <input
        type="text"
        placeholder="Buscar projeto"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        style={{ width: "100%", marginBottom: 20 }}
      />

      {loading && <p className="muted">Carregando…</p>}

      {!loading && (
        <>
          <h2 style={{ marginTop: 0 }}>Meus projetos</h2>
          <div className="target-list">
            {mine.map(renderCard)}
            {!mine.length && (
              <EmptyState
                icon="⬢"
                title="Nenhum projeto seu ainda"
                description='Clique em "+ Novo projeto" para cadastrar o primeiro sistema que você quer auditar.'
                action={<Button onClick={openCreate}>+ Novo projeto</Button>}
              />
            )}
          </div>

          <h2>Exemplos</h2>
          <div className="h2sub">Alvos de demonstração para testar o scanner sem cadastrar nada.</div>
          <div className="target-list">
            {examples.map(renderCard)}
            {!examples.length && term && <p className="muted">Nenhum exemplo bate com a busca.</p>}
          </div>
        </>
      )}

      <Modal open={formOpen} onClose={() => setFormOpen(false)} title={editingId ? "Editar projeto" : "Novo projeto"} size="lg">
        <form onSubmit={submitForm} className="form">
          <FormSection title="Identificação">
            <FormGrid>
              <Field label="Nome" className="span-2">
                <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Ex.: Sistema de cobrança (homologação)" />
              </Field>
              <Field label="URL base" className="span-2" hint="O Sentinela testa esse endereço de fora, como um atacante sem acesso.">
                <input required type="url" value={form.baseUrl} onChange={(e) => setForm({ ...form, baseUrl: e.target.value })} placeholder="https://api.meusistema.com" />
              </Field>
              <Field label="Descrição" optional className="span-2">
                <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </Field>
            </FormGrid>
          </FormSection>

          <details className="form-advanced">
            <summary>
              Testes aprofundados — login, BOLA e BFLA <em>opcional</em>
            </summary>
            <div className="form">
              <p className="form-section-desc">
                Sem isto o Sentinela testa só de fora. Informe o login aqui e cadastre 2 ou mais usuários de teste, de papéis
                diferentes, no menu <b>⋯ → Usuários de teste</b> do projeto.
              </p>

              <FormSection title="Descoberta de rotas">
                <FormGrid>
                  <Field label="Spec OpenAPI/Swagger" optional hint="URL ou caminho. Sem isto, tentamos os caminhos comuns.">
                    <input value={form.openapiUrl} onChange={(e) => setForm({ ...form, openapiUrl: e.target.value })} placeholder="/openapi.json" />
                  </Field>
                  <Field label="WSDL (SOAP/legado)" optional>
                    <input value={form.wsdlUrl} onChange={(e) => setForm({ ...form, wsdlUrl: e.target.value })} placeholder="/service?wsdl" />
                  </Field>
                </FormGrid>
              </FormSection>

              <FormSection title="Login">
                <FormGrid>
                  <Field label="Rota de login">
                    <input value={form.loginPath} onChange={(e) => setForm({ ...form, loginPath: e.target.value })} placeholder="/auth/login" />
                  </Field>
                  <Field label="Campo do token na resposta">
                    <input value={form.tokenField} onChange={(e) => setForm({ ...form, tokenField: e.target.value })} placeholder="token" />
                  </Field>
                  <Field label="Rota que devolve o usuário logado" hint="Usada para confirmar que o token funciona.">
                    <input value={form.protectedProbe} onChange={(e) => setForm({ ...form, protectedProbe: e.target.value })} placeholder="/me" />
                  </Field>
                  <Field label="Rota de cadastro" optional hint="Só se você não vai informar usuários de teste.">
                    <input value={form.registerPath} onChange={(e) => setForm({ ...form, registerPath: e.target.value })} placeholder="/register" />
                  </Field>
                </FormGrid>
              </FormSection>

              <FormSection title="Rotas protegidas">
                <Field label="Rotas que exigem login" hint="Uma por linha. Testadas sem credencial: devem negar o acesso.">
                  <textarea rows={3} value={form.protectedRoutes} onChange={(e) => setForm({ ...form, protectedRoutes: e.target.value })} placeholder={"/contas\n/extrato"} />
                </Field>
              </FormSection>

              <FormSection title="BOLA — acesso ao recurso de outro usuário">
                <FormGrid>
                  <Field
                    label="Método e rota"
                    group
                    hint={<>Use <code>{"{victim}"}</code> para o usuário ou <code>{"{victimId}"}</code> para o ID informado na credencial.</>}
                  >
                    <span className="inline-pair">
                      <select value={form.bolaMethod} onChange={(e) => setForm({ ...form, bolaMethod: e.target.value })} aria-label="Método">
                        {["GET", "PUT", "PATCH", "DELETE", "POST"].map((m) => (
                          <option key={m}>{m}</option>
                        ))}
                      </select>
                      <input value={form.bolaPath} onChange={(e) => setForm({ ...form, bolaPath: e.target.value })} placeholder="/contas/{victim}/saldo" aria-label="Rota" />
                    </span>
                  </Field>
                  <Field label="Corpo JSON" optional hint="Se a operação exigir um corpo.">
                    <input value={form.bolaBody} onChange={(e) => setForm({ ...form, bolaBody: e.target.value })} placeholder='{"email": "x@y.com"}' />
                  </Field>
                </FormGrid>
              </FormSection>

              <FormSection title="BFLA — funções administrativas">
                <Field label="Rotas administrativas" hint="Uma por linha, no formato MÉTODO /rota. Testadas com um usuário comum: devem negar.">
                  <textarea rows={3} value={form.bflaRoutes} onChange={(e) => setForm({ ...form, bflaRoutes: e.target.value })} placeholder={"GET /admin/usuarios\nDELETE /admin/contas/1"} />
                </Field>
              </FormSection>
            </div>
          </details>

          <FormActions>
            <Button type="button" variant="ghost" onClick={() => setFormOpen(false)}>
              Cancelar
            </Button>
            <Button type="submit" loading={saving} loadingLabel="Salvando…">
              Salvar
            </Button>
          </FormActions>
        </form>
      </Modal>

      <Modal open={!!schedTarget} onClose={() => setSchedTarget(null)} title={`Agendar scans — ${schedTarget?.config.name || ""}`}>
        <div className="form">
          <p className="form-section-desc">
            O Sentinela roda o scan sozinho no intervalo escolhido e dispara as integrações. Depois de cada execução, use{" "}
            <b>Comparar com anterior</b> para ver o que piorou. O servidor do Sentinela precisa estar ligado.
          </p>
          <Field
            label="Repetir"
            hint={
              schedule?.enabled
                ? `Próxima execução: ${schedule.nextRunAt ? new Date(schedule.nextRunAt).toLocaleString("pt-BR") : "—"}${
                    schedule.lastRunAt ? ` · última: ${new Date(schedule.lastRunAt).toLocaleString("pt-BR")} (${schedule.lastStatus ?? "—"})` : ""
                  }`
                : undefined
            }
          >
            <select value={schedule?.enabled ? String(schedule.intervalHours) : "0"} onChange={(e) => changeSchedule(e.target.value)} disabled={!schedule}>
              <option value="0">Desligado</option>
              <option value="1">A cada hora</option>
              <option value="6">A cada 6 horas</option>
              <option value="12">A cada 12 horas</option>
              <option value="24">Todo dia</option>
              <option value="168">Toda semana</option>
            </select>
          </Field>
          <FormActions>
            <Button variant="ghost" onClick={() => setSchedTarget(null)}>
              Fechar
            </Button>
          </FormActions>
        </div>
      </Modal>

      <Modal open={!!credTarget} onClose={() => setCredTarget(null)} title={`Usuários de teste — ${credTarget?.config.name || ""}`} size="lg">
        <div className="form">
          <p className="form-section-desc">
            Usuários de <b>homologação</b> que o Sentinela usa para simular um atacante logado. Cadastre um administrador e pelo
            menos dois usuários comuns (o BOLA usa dois). As senhas ficam criptografadas e nunca aparecem de volta.
          </p>

          {creds.length > 0 && (
            <FormSection title={`Cadastrados (${creds.length})`}>
              <div className="cred-list">
                {creds.map((c) => (
                  <div key={c.id} className="cred-row">
                    <div>
                      <b>{c.label}</b> <span className={`badge ${c.role === "admin" ? "badge-custom" : "badge-file"}`}>{c.role}</span>
                      <div className="muted small mono">
                        {c.username} · senha ••••••••{c.resourceId ? ` · id ${c.resourceId}` : ""}
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" className="danger" onClick={() => removeCred(c.id)}>
                      Remover
                    </Button>
                  </div>
                ))}
              </div>
            </FormSection>
          )}

          <form onSubmit={addCred} className="form">
            <FormSection title="Adicionar usuário">
              <FormGrid>
                <Field label="Nome">
                  <input required value={credForm.label} onChange={(e) => setCredForm({ ...credForm, label: e.target.value })} placeholder="Cliente PF" />
                </Field>
                <Field label="Papel">
                  <input required list="roles" value={credForm.role} onChange={(e) => setCredForm({ ...credForm, role: e.target.value })} />
                  <datalist id="roles">
                    <option value="user" />
                    <option value="admin" />
                  </datalist>
                </Field>
                <Field label="Usuário">
                  <input required autoComplete="off" value={credForm.username} onChange={(e) => setCredForm({ ...credForm, username: e.target.value })} />
                </Field>
                <Field label="Senha">
                  <input required type="password" autoComplete="new-password" value={credForm.password} onChange={(e) => setCredForm({ ...credForm, password: e.target.value })} />
                </Field>
                <Field label="ID do recurso" optional hint="Ex.: número da conta, usado no lugar de {victimId}." className="span-2">
                  <input value={credForm.resourceId} onChange={(e) => setCredForm({ ...credForm, resourceId: e.target.value })} />
                </Field>
              </FormGrid>
            </FormSection>
            <FormActions>
              <Button type="button" variant="ghost" onClick={() => setCredTarget(null)}>
                Fechar
              </Button>
              <Button type="submit" loading={credSaving} loadingLabel="Salvando…">
                Adicionar usuário
              </Button>
            </FormActions>
          </form>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!deleteTarget}
        title="Excluir projeto"
        description={`Excluir "${deleteTarget?.config.name || deleteTarget?.name}"? Isso apaga também o histórico de scans dele.`}
        confirmLabel="Excluir"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
