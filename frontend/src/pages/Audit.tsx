import { useEffect, useState } from "react";
import { api, AuditEntry } from "../api/client";
import EmptyState from "../components/ui/EmptyState";
import { useToast } from "../components/ui/ToastContext";

const verbs: Record<string, string> = { POST: "Criou / executou", PUT: "Alterou", PATCH: "Alterou", DELETE: "Excluiu" };

// Traduz "POST /api/targets/123/credentials" em algo legível; o caminho bruto fica no tooltip.
function describe(e: AuditEntry): string {
  const p = e.path.replace(/^\/api\//, "");
  const rules: [RegExp, string][] = [
    [/^auth\/login/, "Tentativa de login"],
    [/^auth\/bootstrap/, "Criação do administrador inicial"],
    [/^scans$/, "Rodou um scan"],
    [/^scans\//, "Scan"],
    [/^targets\/[^/]+\/credentials/, "Credenciais de teste"],
    [/^targets\/[^/]+\/schedule/, "Agendamento de scan"],
    [/^targets/, "Projeto"],
    [/^findings/, "Triagem de achado"],
    [/^integrations\/webhooks/, "Integração: webhook"],
    [/^integrations\/slack/, "Integração: Slack"],
    [/^integrations\/github/, "Integração: GitHub"],
    [/^users/, "Usuário"],
    [/^ai\/test/, "Teste da conexão com a IA"],
  ];
  const what = rules.find(([re]) => re.test(p))?.[1] ?? p;
  const verb = /login|bootstrap|ai\/test/.test(p) || e.path === "/api/scans" ? "" : `${verbs[e.method] ?? e.method}: `;
  return `${verb}${what}`;
}

export default function AuditPage() {
  const toast = useToast();
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listAudit().then(setRows).catch(toast.error).finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Auditoria</h1>
          <div className="eyebrow">Quem fez o quê: registra toda ação que cria, altera ou exclui algo. Não guarda senhas nem o conteúdo enviado.</div>
        </div>
      </div>
      {loading && <p className="muted">Carregando…</p>}
      {!loading && !rows.length && <EmptyState icon="☰" title="Nenhum registro ainda" description="As ações dos usuários aparecem aqui." />}
      {rows.length > 0 && (
        <div className="audit-table">
          {rows.map((r) => (
            <div key={r.id} className="audit-row" title={`${r.method} ${r.path}`}>
              <span className="mono muted small">{new Date(r.createdAt).toLocaleString("pt-BR")}</span>
              <span className="audit-user">{r.user ?? "—"}</span>
              <span>{describe(r)}</span>
              <span className={`pill ${r.status < 400 ? "pill-ok" : "pill-fail"}`}>{r.status < 400 ? "ok" : `erro ${r.status}`}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
