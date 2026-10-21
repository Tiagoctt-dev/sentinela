export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

export type Resolution = "open" | "resolved" | "risk_accepted";

export interface Finding {
  rowId: string;
  id: string;
  category: string;
  title: string;
  status: "PASS" | "FAIL" | "WARN" | "SKIP";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  detail: string;
  recommendation: string;
  evidence: string;
  source: string;
  owasp: string;
  data: unknown;
  aiRec?: Record<string, { provider: string; prioridade?: string; risco?: string; acao?: string }> | null;
  resolution: Resolution;
  resolutionNote?: string | null;
}

export interface FindingWithContext extends Finding {
  scanId: string;
  targetId: string;
  targetName: string;
  createdAt: string;
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
}

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
  totals: { PASS: number; FAIL: number; WARN: number; SKIP: number };
  policy: PolicyResult | null;
  createdAt: string;
  createdBy?: string | null;
  origin?: string | null;
}

export interface ScanDetail extends ScanSummary {
  categories: CategoryScore[];
  ai: AiProviderResult[];
  policy: PolicyResult | null;
  findings: Finding[];
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
  wsdlUrl?: string;
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
}

export interface ScanComparison {
  previous: { id: string; createdAt: string; overall: number; verdict: string } | null;
  delta?: number;
  new?: { rowId: string; id: string; title: string; severity: string; status: string }[];
  fixed?: { rowId: string; id: string; title: string; severity: string; status: string }[];
  worse?: { rowId: string; id: string; title: string; severity: string; status: string }[];
  persisting?: number;
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
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
  });
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
    throw new ApiError(res.status, message || `Erro ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  authStatus: () => request<{ authRequired: boolean; hasUsers: boolean }>("/api/auth/status"),
  bootstrap: (body: { name: string; email: string; password: string }) =>
    request<{ token: string; user: AuthUser }>("/api/auth/bootstrap", { method: "POST", body: JSON.stringify(body) }),
  login: (body: { email: string; password: string }) =>
    request<{ token: string; user: AuthUser }>("/api/auth/login", { method: "POST", body: JSON.stringify(body) }),
  me: () => request<AuthUser>("/api/auth/me"),

  listUsers: () => request<AppUser[]>("/api/users"),
  createUser: (body: { name: string; email: string; password: string; role: string }) =>
    request<AppUser>("/api/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: Partial<{ name: string; role: string; active: boolean; password: string }>) =>
    request<AppUser>(`/api/users/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteUser: (id: string) => request<void>(`/api/users/${id}`, { method: "DELETE" }),
  listAudit: () => request<AuditEntry[]>("/api/audit"),

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
  runScan: (body: { targetId?: string; target?: string; url?: string; static?: boolean; dynamic?: boolean; ai?: boolean }) =>
    request<ScanDetail>("/api/scans", { method: "POST", body: JSON.stringify(body) }),

  listFindings: (params: { status?: string; severity?: string; resolution?: string; targetId?: string; q?: string } = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]).toString();
    return request<FindingWithContext[]>(`/api/findings${qs ? `?${qs}` : ""}`);
  },
  getFinding: (rowId: string) => request<FindingWithContext>(`/api/findings/${rowId}`),
  updateFinding: (rowId: string, body: { resolution: Resolution; resolutionNote?: string }) =>
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
