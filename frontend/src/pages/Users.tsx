import { useEffect, useState } from "react";
import { api, AppUser } from "../api/client";
import { useAuth } from "../components/AuthContext";
import Button from "../components/ui/Button";
import { Field, FormActions, FormGrid } from "../components/ui/Form";
import ConfirmDialog from "../components/ui/ConfirmDialog";
import Modal from "../components/ui/Modal";
import { useToast } from "../components/ui/ToastContext";

const roleLabel: Record<string, string> = { admin: "Administrador", analyst: "Analista", viewer: "Somente leitura" };
const roleHelp: Record<string, string> = {
  admin: "Tudo: usuários, credenciais de teste, integrações, auditoria.",
  analyst: "Cadastra projetos, roda scans e faz a triagem dos achados.",
  viewer: "Só consulta scans e achados.",
};
const emptyForm = { name: "", email: "", password: "", role: "analyst" };

export default function UsersPage() {
  const toast = useToast();
  const { user: me } = useAuth();
  const [users, setUsers] = useState<AppUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AppUser | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [pwTarget, setPwTarget] = useState<AppUser | null>(null);
  const [newPw, setNewPw] = useState("");

  useEffect(() => {
    api.listUsers().then(setUsers).catch(toast.error).finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const created = await api.createUser(form);
      setUsers((prev) => [...prev, created]);
      setForm(emptyForm);
      setFormOpen(false);
    } catch (err) {
      toast.error(err);
    } finally {
      setSaving(false);
    }
  }

  async function patch(u: AppUser, body: Partial<{ role: string; active: boolean; password: string }>) {
    try {
      const updated = await api.updateUser(u.id, body);
      setUsers((prev) => prev.map((x) => (x.id === u.id ? updated : x)));
      return true;
    } catch (err) {
      toast.error(err);
      return false;
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.deleteUser(deleteTarget.id);
      setUsers((prev) => prev.filter((x) => x.id !== deleteTarget.id));
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
          <h1>Usuários</h1>
          <div className="eyebrow">Quem pode entrar no Sentinela e o que cada pessoa pode fazer.</div>
        </div>
        <Button onClick={() => setFormOpen(true)}>+ Novo usuário</Button>
      </div>

      {loading && <p className="muted">Carregando…</p>}
      <div className="cred-list">
        {users.map((u) => (
          <div key={u.id} className="cred-row user-row">
            <div style={{ minWidth: 0 }}>
              <b>{u.name}</b> {u.id === me?.id && <span className="badge badge-custom">você</span>}{" "}
              {!u.active && <span className="badge badge-file">desativado</span>}
              <div className="muted small mono">
                {u.email} · último acesso: {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString("pt-BR") : "nunca"}
              </div>
            </div>
            <div className="user-actions">
              <select value={u.role} onChange={(e) => patch(u, { role: e.target.value })} aria-label={`Papel de ${u.name}`}>
                {Object.entries(roleLabel).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
              <Button variant="ghost" size="sm" onClick={() => { setPwTarget(u); setNewPw(""); }}>Nova senha</Button>
              <Button variant="ghost" size="sm" onClick={() => patch(u, { active: !u.active })} disabled={u.id === me?.id}>
                {u.active ? "Desativar" : "Ativar"}
              </Button>
              <Button variant="ghost" size="sm" className="danger" onClick={() => setDeleteTarget(u)} disabled={u.id === me?.id}>
                Excluir
              </Button>
            </div>
          </div>
        ))}
      </div>

      <Modal open={formOpen} onClose={() => setFormOpen(false)} title="Novo usuário">
        <form onSubmit={create} className="form">
          <FormGrid>
            <Field label="Nome" className="span-2">
              <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="E-mail" className="span-2">
              <input required type="text" inputMode="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </Field>
            <Field label="Senha inicial" hint="Mínimo de 10 caracteres." className="span-2">
              <input required type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </Field>
            <Field label="Papel" hint={roleHelp[form.role]} className="span-2">
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {Object.entries(roleLabel).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </Field>
          </FormGrid>
          <FormActions>
            <Button type="button" variant="ghost" onClick={() => setFormOpen(false)}>Cancelar</Button>
            <Button type="submit" loading={saving} loadingLabel="Criando…">Criar usuário</Button>
          </FormActions>
        </form>
      </Modal>

      <Modal open={!!pwTarget} onClose={() => setPwTarget(null)} title={`Nova senha — ${pwTarget?.name ?? ""}`}>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (pwTarget && (await patch(pwTarget, { password: newPw }))) {
              toast.success("Senha atualizada.");
              setPwTarget(null);
            }
          }}
          className="form"
        >
          <Field label="Nova senha" hint="Mínimo de 10 caracteres.">
            <input required type="password" autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
          </Field>
          <FormActions>
            <Button type="button" variant="ghost" onClick={() => setPwTarget(null)}>Cancelar</Button>
            <Button type="submit">Salvar senha</Button>
          </FormActions>
        </form>
      </Modal>

      <ConfirmDialog
        open={!!deleteTarget}
        title="Excluir usuário"
        description={`Excluir ${deleteTarget?.name} (${deleteTarget?.email})? Os scans que essa pessoa executou continuam no histórico.`}
        confirmLabel="Excluir"
        loading={deleting}
        onConfirm={remove}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
