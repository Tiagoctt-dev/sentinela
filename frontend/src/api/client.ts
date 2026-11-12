export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

export type Resolution = "open" | "resolved" | "risk_accepted";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
/** Estado do teste: o que realmente aconteceu. Distinto de severidade (impacto) e de confiança (grau de prova). */
export type FindingState = "vulnerable" | "likely" | "inconclusive" | "error" | "passed" | "not_run" | "not_applicable";
export type Confidence = "confirmed" | "indicative" | "none";

export interface Reference {
  label: string;
  url: string;
}

export interface FindingAsset {
  method?: string;
  path?: string;
  param?: string;
  url?: string;
  host?: string;
  httpStatus?: number;
}

/** Texto editorial da verificação (vem do backend; a UI não inventa conteúdo). */
export interface FindingMeta {
  policyId?: string;
  headline?: string;
  summary?: string;
  technical?: string;
  impact?: string;
  exploitation?: string;
  prerequisites?: string;
  passWhen?: string;
  failWhen?: string;
  limitations?: string;
  severityReason?: string;
  scopeNote?: string;
  proof?: "confirmed" | "indicative";
  references?: Reference[];
}

export interface Finding {
  rowId: string;
  id: string;
  category: string;
  title: string;
  status: "PASS" | "FAIL" | "WARN" | "SKIP";
  severity: Severity;
  detail: string;
  recommendation: string;
  evidence: string;
  source: string;
  owasp: string;
  data: { requiresLogin?: boolean; [k: string]: unknown } | null;
  state: FindingState;
  confidence: Confidence;
  asset: FindingAsset | null;
  meta: FindingMeta | null;
  aiRec?: Record<string, { provider: string; prioridade?: string; risco?: string; acao?: string }> | null;
  resolution: Resolution;
  resolutionNote?: string | null;
  resolutionExpiresAt?: string | null;
  resolutionBy?: string | null;
}

/** Histórico do mesmo achado (mesma política e mesmo ativo) nas últimas execuções do projeto. */
export interface FindingHistory {
  timeline: { scanId: string; createdAt: string; state: FindingState | null }[];
  firstSeenAt: string | null;
  occurrences: number;
  regression: boolean;
  windowScans: number;
}

export interface FindingWithContext extends Finding {
  scanId: string;
  targetId: string;
  targetName: string;
  createdAt: string;
  history?: FindingHistory;
}

export interface CategoryScore {
  key: string;
  label: string;
  short: string;
  score: number | null;
  evaluated: number;
  counts: { PASS: number; FAIL: number; WARN: number; SKIP: number };
}

export interface AiProviderResult {
  provider: string;
  key: string;
  enabled: boolean;
  summary?: string;
  model?: string;
  reason?: string;
  count?: number;
}

export interface PolicyResult {
  policyId: string;
  policyName: string;
  passed: boolean;
  reason: string;
  violations: string[];
  pending?: string[];
}

export interface ScopeCheck {
  id: string;
  title: string;
  reason: string;
}

/** O que foi e o que NÃO foi executado em um scan — base da cobertura. */
export interface ScanScope {
  mode: "external" | "authenticated";
  credentials: { count: number; roles: string[] };
  specFound: boolean;
  codeAnalyzed: boolean;
  mutationsAllowed: boolean;
  checksPlanned: number;
  checksExecuted: number;
  coveragePct: number;
  notRun: ScopeCheck[];
  notApplicable: ScopeCheck[];
  limitations: string[];
}

export type StateCounts = Record<FindingState, number>;

export interface Policy {
  id: string;
  name: string;
  description: string;
  scope: string;
  status: string;
  editable: boolean;
}

export interface ScanSummary {
  id: string;
  targetId: string;
  targetName: string;
  mode: string;
  overall: number;
  verdict: string;
  totals: { PASS: number; FAIL: number; WARN: number; SKIP: number; states?: StateCounts };
  policy: PolicyResult | null;
  createdAt: string;
  createdBy?: string | null;
  origin?: string | null;
  /** Resumo do escopo na lista; o escopo completo vem em ScanDetail. Nulo em scans anteriores ao registro de escopo. */
  scope: { mode: ScanScope["mode"]; coveragePct: number } | ScanScope | null;
}

export interface ScanDetail extends ScanSummary {
  categories: CategoryScore[];
  ai: AiProviderResult[];
  policy: PolicyResult | null;
  findings: Finding[];
  scope: ScanScope | null;
}

export interface RouteCheck {
  checkId: string;
  title: string;
  findingRowId?: string;
  severity: Severity;
  state: FindingState;
  httpStatus: number | null;
  note: string | null;
}

export type RouteState = "vulnerable" | "likely" | "error" | "inconclusive" | "passed" | "not_run" | "not_tested";

export interface RouteItem {
  method: string;
  path: string;
  discovered: boolean;
  known: boolean;
  tested: boolean;
  state: RouteState;
  sources: string[];
  checks: RouteCheck[];
  label: string | null;
}

export interface RoutesView {
  routes: RouteItem[];
  counts: {
    routes: number;
    known: number;
    tested: number;
    pending: number;
    byState: Record<RouteState, number>;
    checks: Partial<Record<FindingState, number>>;
  };
  pendingChecks: ScopeCheck[];
  notApplicableChecks: ScopeCheck[];
}

export interface Dashboard {
  projects: number;
  findings: {
    bySeverity: Record<Severity, number>;
    byState: StateCounts;
    openConfirmedOrLikely: number;
    byCategory: { category: string; vulnerable: number; likely: number }[];
  };
  coverage: { avgPct: number | null; scansWithScope: number };
  routes: { routes: number; known: number; tested: number; pending: number } | null;
  trend: { scanId: string; createdAt: string; score: number; vulnerable: number; likely: number; coveragePct: number | null; mode: string | null }[];
  trendNote: string | null;
  missing: string[];
}

export interface TargetConfig {
  name: string;
  description?: string;
  baseUrl?: string;
  projectPath?: string;
  endpoints?: { protectedGet?: string[]; [k: string]: unknown };
  auth?: { login?: string; register?: string; tokenField?: string; scheme?: string; protectedProbe?: string; [k: string]: unknown };
  bola?: { method?: string; path?: string; body?: unknown };
  bfla?: { method: string; path: string }[];
  massAssignment?: Record<string, unknown>;
  openapiUrl?: string;
  openapiSpecSummary?: { title: string | null; version: string | null; paths: number; operations: number };
  wsdlUrl?: string;
  allowMutations?: boolean;
}

export interface TargetInfo {
  id: string;
  name: string;
  source: "file" | "custom";
  config: TargetConfig;
  createdAt: string;
}

export interface TargetInput {
  name: string;
  baseUrl: string;
  description?: string;
  endpoints?: TargetConfig["endpoints"];
  auth?: TargetConfig["auth"];
  bola?: TargetConfig["bola"];
  bfla?: TargetConfig["bfla"];
  openapiUrl?: string;
  wsdlUrl?: string;
  allowMutations?: boolean;
}

export interface ScanComparison {
  previous: { id: string; createdAt: string; overall: number; verdict: string } | null;
  delta?: number;
  new?: ComparedFinding[];
  fixed?: ComparedFinding[];
  worse?: ComparedFinding[];
  /** Estavam com problema antes e não puderam ser reavaliadas agora — NÃO contam como corrigidas. */
  notComparable?: ComparedFinding[];
  persisting?: number;
}

export interface ComparedFinding {
  rowId: string;
  id: string;
  title: string;
  severity: Severity;
  status: string;
  state: FindingState;
}

export interface Credential {
  id: string;
  label: string;
  role: string;
  username: string;
  resourceId: string | null;
  passwordSet: boolean;
  createdAt: string;
}

export interface CredentialInput {
  label: string;
  role: string;
  username: string;
  password: string;
  resourceId?: string;
}

export interface Webhook {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  lastStatus: string | null;
  lastTriggeredAt: string | null;
  createdAt: string;
}

export interface GithubIntegration {
  id: string;
  repo: string;
  tokenMasked: string;
  enabled: boolean;
  lastStatus: string | null;
  lastTriggeredAt: string | null;
  createdAt: string;
}

export interface SlackIntegration {
  id: string;
  name: string;
  webhookUrl: string;
  enabled: boolean;
  lastStatus: string | null;
  lastTriggeredAt: string | null;
  createdAt: string;
}

export type Coverage = "coberto" | "parcial" | "nao_coberto";

export interface OwaspCheck {
  id: string;
  title: string;
  kind: "static" | "dynamic";
  severity: Finding["severity"];
  how: string;
  needsConfig: boolean;
  proof: "confirmed" | "indicative" | null;
  objective: string | null;
  prerequisites: string | null;
  passWhen: string | null;
  failWhen: string | null;
  limitations: string | null;
  severityReason: string | null;
  references: Reference[];
}

export interface OwaspItem {
  id: string;
  name: string;
  description: string;
  coverage: Coverage;
  coverageNote: string | null;
  checks: OwaspCheck[];
  stats: { pass: number; fail: number; warn: number; open: number };
  openFindings: { rowId: string; title: string; severity: Finding["severity"]; targetName: string }[];
}

export interface PolicyCatalog {
  gate: { name: string; summary: string; verdicts: { label: string; range: string }[]; scoring: string[] };
  items: OwaspItem[];
  summary: { covered: number; partial: number; notCovered: number; total: number; checks: number };
}

export interface AiTestResult {
  provider: string;
  configured: boolean;
  ok: boolean;
  model?: string;
  latencyMs?: number;
  keyHint?: string;
  message: string;
  transient?: boolean;
}

export interface StatsSummary {
  scoreAvg: number | null;
  criticosAbertos: number;
  endpointsCobertos: number;
  totalScans: number;
  totalProjects: number;
  lastScan: { id: string; targetName: string; createdAt: string } | null;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const TOKEN_KEY = "sentinela.token";
export const getToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
};
export const setToken = (t: string) => {
  try {
    localStorage.setItem(TOKEN_KEY, t);
  } catch {
    /* sem storage: a sessão vale só até recarregar */
  }
};
export const clearToken = () => {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignora */
  }
};

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst" | "viewer";
}
export interface AppUser extends AuthUser {
  active: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}
export interface AuditEntry {
  id: string;
  user: string | null;
  method: string;
  path: string;
  status: number;
  ip: string | null;
  createdAt: string;
}
export interface Schedule {
  enabled: boolean;
  intervalHours: number | null;
  nextRunAt: string | null;
  lastRunAt: string | null;
  lastStatus: string | null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(init?.headers || {}),
      },
    });
  } catch {
    throw new ApiError(0, "Não foi possível conectar ao servidor do Sentinela. Verifique se o serviço está no ar e tente de novo.");
  }
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    clearToken();
    window.dispatchEvent(new Event("sentinela:unauthorized"));
  }
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    let message = raw;
    try {
      const parsed = JSON.parse(raw);
      message = parsed?.detail ?? raw;
    } catch {
      // corpo não é JSON — usa o texto cru
    }
    throw new ApiError(res.status, friendlyMessage(res.status, typeof message === "string" ? message : ""));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** Mensagem útil para o usuário: usa o texto do servidor quando há, e explica o que fazer quando não há. */
export function friendlyMessage(status: number, serverMessage: string): string {
  const msg = serverMessage.trim();
  if (msg && !msg.startsWith("<")) return msg;
  if (status === 401) return "Sua sessão expirou. Entre novamente.";
  if (status === 403) return "Seu perfil não tem permissão para esta ação. Fale com um administrador.";
  if (status === 404) return "Não encontramos o que você pediu. Pode ter sido removido.";
  if (status === 409) return "Outra operação está em andamento neste item. Aguarde terminar e tente de novo.";
  if (status === 413) return "O arquivo é grande demais.";
  if (status === 429) return "Muitas tentativas seguidas. Aguarde alguns minutos e tente de novo.";
  if (status >= 500) return "O servidor teve um problema ao processar o pedido. Tente de novo em instantes; se persistir, avise a equipe.";
  return `Não foi possível concluir (erro ${status}).`;
}

async function requestRaw(path: string, init?: RequestInit): Promise<Response> {
  const token = getToken();
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(init?.headers || {}) } });
  } catch {
    throw new ApiError(0, "Não foi possível conectar ao servidor do Sentinela. Verifique se o serviço está no ar e tente de novo.");
  }
  if (!res.ok) throw new ApiError(res.status, friendlyMessage(res.status, await res.text().catch(() => "")));
  return res;
}

export interface Page<T> {
  items: T[];
  total: number;
}

async function requestPage<T>(path: string): Promise<Page<T>> {
  const res = await requestRaw(path, { headers: { "content-type": "application/json" } });
  const items = (await res.json()) as T[];
  const total = Number(res.headers.get("x-total-count"));
  return { items, total: Number.isFinite(total) && total > 0 ? total : items.length };
}

export interface RetentionStatus {
  policy: { auditDays: number; scanDays: number; note: string };
  stored: { auditEntries: number; scans: number; findings: number };
}

export const api = {
  authStatus: () => request<{ authRequired: boolean; hasUsers: boolean }>("/api/auth/status"),
  bootstrap: (body: { name: string; email: string; password: string }) =>
    request<{ token: string; user: AuthUser }>("/api/auth/bootstrap", { method: "POST", body: JSON.stringify(body) }),
  login: (body: { email: string; password: string }) =>
    request<{ token: string; user: AuthUser }>("/api/auth/login", { method: "POST", body: JSON.stringify(body) }),
  me: () => request<AuthUser>("/api/auth/me"),
  logoutServer: () => request<void>("/api/auth/logout", { method: "POST" }),
  changePassword: (body: { currentPassword: string; newPassword: string }) =>
    request<{ token: string; user: AuthUser }>("/api/auth/change-password", { method: "POST", body: JSON.stringify(body) }),

  listUsers: () => request<AppUser[]>("/api/users"),
  createUser: (body: { name: string; email: string; password: string; role: string }) =>
    request<AppUser>("/api/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: Partial<{ name: string; role: string; active: boolean; password: string }>) =>
    request<AppUser>(`/api/users/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteUser: (id: string) => request<void>(`/api/users/${id}`, { method: "DELETE" }),
  listAudit: () => request<AuditEntry[]>("/api/audit"),
  listAuditPage: (offset = 0, limit = 200) => requestPage<AuditEntry>(`/api/audit?limit=${limit}&offset=${offset}`),
  getRetention: () => request<RetentionStatus>("/api/admin/retention"),
  runRetention: () => request<{ expiredRiskAcceptances: number; removed: Record<string, number> }>("/api/admin/retention/run", { method: "POST" }),

  getSchedule: (targetId: string) => request<Schedule>(`/api/targets/${targetId}/schedule`),
  setSchedule: (targetId: string, intervalHours: number) =>
    request<Schedule>(`/api/targets/${targetId}/schedule`, { method: "PUT", body: JSON.stringify({ intervalHours }) }),
  clearSchedule: (targetId: string) => request<void>(`/api/targets/${targetId}/schedule`, { method: "DELETE" }),

  listTargets: () => request<TargetInfo[]>("/api/targets"),
  createTarget: (body: TargetInput) => request<TargetInfo>("/api/targets", { method: "POST", body: JSON.stringify(body) }),
  updateTarget: (id: string, body: Partial<TargetInput>) =>
    request<TargetInfo>(`/api/targets/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteTarget: (id: string) => request<void>(`/api/targets/${id}`, { method: "DELETE" }),

  listCredentials: (targetId: string) => request<Credential[]>(`/api/targets/${targetId}/credentials`),
  createCredential: (targetId: string, body: CredentialInput) =>
    request<Credential>(`/api/targets/${targetId}/credentials`, { method: "POST", body: JSON.stringify(body) }),
  deleteCredential: (targetId: string, id: string) =>
    request<void>(`/api/targets/${targetId}/credentials/${id}`, { method: "DELETE" }),

  listScans: (targetId?: string) => request<ScanSummary[]>(`/api/scans${targetId ? `?targetId=${targetId}` : ""}`),
  getScan: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  compareScan: (id: string) => request<ScanComparison>(`/api/scans/${id}/compare`),
  deleteScan: (id: string) => request<void>(`/api/scans/${id}`, { method: "DELETE" }),
  scanProgress: () => request<{ running: { targetId: string; label: string; done: number; total: number; startedAt: number }[] }>("/api/scans/progress"),
  uploadSpec: (targetId: string, text: string) =>
    request<TargetInfo>(`/api/targets/${targetId}/openapi-spec`, { method: "PUT", body: text, headers: { "content-type": "text/plain" } }),
  removeSpec: (targetId: string) => request<void>(`/api/targets/${targetId}/openapi-spec`, { method: "DELETE" }),
  /** Baixa o SARIF 2.1.0 do scan (com a sessão atual) e devolve o texto. */
  scanSarif: async (id: string) => (await requestRaw(`/api/scans/${id}/sarif`)).text(),
  runScan: (body: { targetId?: string; target?: string; url?: string; static?: boolean; dynamic?: boolean; ai?: boolean; profile?: "full" | "safe" }) =>
    request<ScanDetail>("/api/scans", { method: "POST", body: JSON.stringify(body) }),

  scanRoutes: (id: string) => request<RoutesView>(`/api/scans/${id}/routes`),
  getDashboard: (targetId?: string) => request<Dashboard>(`/api/dashboard${targetId ? `?targetId=${targetId}` : ""}`),

  listFindings: (params: { status?: string; state?: string; confidence?: string; category?: string; severity?: string; resolution?: string; targetId?: string; q?: string } = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]).toString();
    return request<FindingWithContext[]>(`/api/findings${qs ? `?${qs}` : ""}`);
  },
  countFindings: (params: { resolution?: string; targetId?: string } = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]).toString();
    return request<{ count: number }>(`/api/findings/count${qs ? `?${qs}` : ""}`);
  },
  getFinding: (rowId: string) => request<FindingWithContext>(`/api/findings/${rowId}`),
  updateFinding: (rowId: string, body: { resolution: Resolution; resolutionNote?: string; expiresInDays?: number }) =>
    request<FindingWithContext>(`/api/findings/${rowId}`, { method: "PATCH", body: JSON.stringify(body) }),

  getStats: () => request<StatsSummary>("/api/stats/summary"),
  listPolicies: () => request<Policy[]>("/api/policies"),
  getPolicyCatalog: () => request<PolicyCatalog>("/api/policies/owasp"),
  testAi: () => request<AiTestResult[]>("/api/ai/test", { method: "POST" }),

  listWebhooks: () => request<Webhook[]>("/api/integrations/webhooks"),
  createWebhook: (body: { name: string; url: string }) =>
    request<Webhook>("/api/integrations/webhooks", { method: "POST", body: JSON.stringify(body) }),
  updateWebhook: (id: string, body: Partial<{ name: string; url: string; enabled: boolean }>) =>
    request<Webhook>(`/api/integrations/webhooks/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteWebhook: (id: string) => request<void>(`/api/integrations/webhooks/${id}`, { method: "DELETE" }),
  testWebhook: (id: string) => request<Webhook>(`/api/integrations/webhooks/${id}/test`, { method: "POST" }),

  listGithub: () => request<GithubIntegration[]>("/api/integrations/github"),
  createGithub: (body: { repo: string; token: string }) =>
    request<GithubIntegration>("/api/integrations/github", { method: "POST", body: JSON.stringify(body) }),
  updateGithub: (id: string, body: Partial<{ repo: string; token: string; enabled: boolean }>) =>
    request<GithubIntegration>(`/api/integrations/github/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteGithub: (id: string) => request<void>(`/api/integrations/github/${id}`, { method: "DELETE" }),
  testGithub: (id: string) => request<GithubIntegration>(`/api/integrations/github/${id}/test`, { method: "POST" }),

  listSlack: () => request<SlackIntegration[]>("/api/integrations/slack"),
  createSlack: (body: { name: string; webhookUrl: string }) =>
    request<SlackIntegration>("/api/integrations/slack", { method: "POST", body: JSON.stringify(body) }),
  updateSlack: (id: string, body: Partial<{ name: string; webhookUrl: string; enabled: boolean }>) =>
    request<SlackIntegration>(`/api/integrations/slack/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteSlack: (id: string) => request<void>(`/api/integrations/slack/${id}`, { method: "DELETE" }),
  testSlack: (id: string) => request<SlackIntegration>(`/api/integrations/slack/${id}/test`, { method: "POST" }),
};
