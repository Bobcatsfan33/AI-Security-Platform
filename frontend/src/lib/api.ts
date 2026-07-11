// Typed fetch wrappers around the control-plane /v1 surface.
//
// Auth: a Bearer JWT held in localStorage. The login page either pastes
// a dev token in directly, or initiates the OIDC redirect to
// /v1/auth/oidc/{org_slug}/login and stores the token returned by the
// callback. The callback currently returns JSON; the login page reads
// that and stashes the token.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

const TOKEN_KEY = "platform_access_token";
const USER_KEY = "platform_user";

export type Session = {
  access_token: string;
  user: {
    id: string;
    email: string;
    name: string;
    role: string;
    org_id: string;
  };
};

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setSession(s: Session): void {
  localStorage.setItem(TOKEN_KEY, s.access_token);
  localStorage.setItem(USER_KEY, JSON.stringify(s.user));
}

export function getUser(): Session["user"] | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, detail: unknown, message: string) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init.headers as Record<string, string>) || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (resp.status === 204) return undefined as T;
  const body = await resp.text();
  const parsed = body ? JSON.parse(body) : undefined;
  if (!resp.ok) {
    throw new ApiError(
      resp.status,
      parsed,
      typeof parsed?.detail === "string"
        ? parsed.detail
        : `${resp.status} ${resp.statusText}`,
    );
  }
  return parsed as T;
}

// Raw-text fetch for endpoints that return non-JSON (e.g. the reports API
// serves text/markdown). Same auth + error handling as request(), but returns
// the untouched body instead of JSON-parsing it.
async function requestText(path: string, init: RequestInit = {}): Promise<string> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  const body = await resp.text();
  if (!resp.ok) {
    let detail: unknown = body;
    try {
      detail = body ? JSON.parse(body) : undefined;
    } catch {
      // non-JSON error body — keep the raw text
    }
    const message =
      typeof (detail as { detail?: unknown })?.detail === "string"
        ? (detail as { detail: string }).detail
        : `${resp.status} ${resp.statusText}`;
    throw new ApiError(resp.status, detail, message);
  }
  return body;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  getText: (path: string) => requestText(path),
  post: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "POST", body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

// ───────────────────────────────────────── domain types

export type Asset = {
  id: string;
  org_id: string;
  name: string;
  description: string | null;
  status: string;
  provider: string;
  model_name: string;
  environment: string;
  exposure: string;
  data_classification: string;
  open_findings_count: number;
  critical_findings_count: number;
  last_evaluation_score: number | null;
  last_evaluation_date: string | null;
  runtime_agent_connected: boolean;
  tags: string[];
  created_at: string;
  updated_at: string;
};

export type Evaluation = {
  id: string;
  org_id: string;
  asset_id: string;
  status: string;
  eval_type: string;
  score: number;
  risk_label: string | null;
  tests_run: number;
  tests_passed: number;
  tests_failed: number;
  findings_count: number;
  critical_findings: number;
  summary: Record<string, unknown>;
  model_cost_usd: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
};

export type Finding = {
  id: string;
  evaluation_id: string;
  asset_id: string;
  test_case_id: string;
  title: string;
  category: string;
  severity: string;
  risk_score: number;
  confidence: number;
  attack_succeeded: boolean;
  prompt_sent: string | null;
  response_received: string | null;
  judge_reasoning: string | null;
  recommendation: string | null;
  remediation_status: string;
  remediation_notes: string | null;
  created_at: string;
};

export type Connector = {
  id: string;
  org_id: string;
  provider: string;
  display_name: string;
  model: string;
  api_key_ref_present: boolean;
  config: Record<string, unknown>;
  verification_status: Record<string, unknown>;
  is_active: boolean;
  created_at: string;
};

// ───────────────────────────────────────── Tier 3 types

export type DashboardRuntimeOverview = {
  time_range: string;
  total_events: number;
  blocked_events: number;
  block_rate_pct: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  by_event_type: Array<{ event_type: string; count: number }>;
  by_pipeline_exit_stage: Array<{ pipeline_exit_stage: string; count: number }>;
  timeline: Array<{ bucket: string; count: number; blocked: number }>;
};

export type DashboardTrafficRow = {
  asset_id: string;
  total_events: number;
  inbound: number;
  outbound: number;
  blocked: number;
  avg_latency_ms: number;
  estimated_cost_usd: number;
  token_input: number;
  token_output: number;
};

export type DashboardPolicyEffectiveness = {
  time_range: string;
  stage1_hits: number;
  stage2_hits: number;
  stage3_hits: number;
  no_match: number;
  stage1_avg_us: number;
  stage2_avg_us: number;
  stage3_avg_ms: number;
  top_block_reasons: Array<{ block_reason: string; count: number }>;
};

export type Anomaly = {
  id: string;
  org_id: string;
  asset_id: string;
  detected_at: string;
  kind: "volume_spike" | "novel_transition" | "risk_inflation";
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  detail: Record<string, unknown>;
};

export type ThreatIntelStatus = {
  samples_processed: number;
  cluster_count: number;
  novel_count: number;
  last_built_at: string | null;
};

export type ThreatIntelCluster = {
  id: string;
  category: string;
  severity: string;
  size: number;
  supporting_orgs: number;
  top_keywords: string[];
  top_controls: string[];
  fingerprint: string;
};

export type ComplianceFramework = {
  id: string;
  name: string;
  control_count: number;
  controls: Array<{ id: string; title: string }>;
};

export type TestCase = {
  id: string;
  name: string;
  description: string | null;
  category: string;
  sub_category: string | null;
  severity: string;
  attack_type: string;
  prompts: Array<Record<string, unknown>>;
  expected_behavior: string;
  success_criteria: Record<string, unknown>;
  failure_indicators: string[];
  tags: string[];
  control_mappings: string[];
  mitre_atlas_id: string | null;
  source: string;
  is_global: boolean;
  effectiveness_score: number;
  is_regression: boolean;
  created_at: string;
};

export type McpToolProfile = {
  id: string;
  tool_name: string;
  access_mode: string;
  description: string;
  allowed_params: string[];
  forbidden_params: string[];
  param_constraints: Record<string, Record<string, unknown>>;
  is_builtin: boolean;
};

export type McpViolation = {
  id: string;
  session_id: string;
  tool_name: string;
  recommendation: string;
  risk_score: number;
  violations: Array<Record<string, unknown>>;
  chain_matches: Array<Record<string, unknown>>;
  resolution_status: string;
  resolution_notes: string | null;
  resolved_at: string | null;
  created_at: string;
};

export type NarrativeStatus =
  | "open"
  | "confirmed"
  | "false_positive"
  | "suppressed"
  | "resolved";

export type ThreatNarrative = {
  id: string;
  correlation_id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  kind: string;
  confidence: number;
  agents: string[];
  asset_id: string;
  signal_count: number;
  status: NarrativeStatus;
  assignee: string;
  rationale: string;
  created_at: string;
  disposition_at: string | null;
  contributing: Array<Record<string, unknown>>;
  causal_timeline: Array<Record<string, unknown>>;
};

export type DispositionInput = {
  status: NarrativeStatus;
  rationale?: string;
  assignee?: string;
};

export const narratives = {
  list: (params: { status?: string; severity?: string } = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => Boolean(v)) as [string, string][],
    ).toString();
    return api.get<ThreatNarrative[]>(`/v1/narratives${qs ? `?${qs}` : ""}`);
  },
  get: (id: string) => api.get<ThreatNarrative>(`/v1/narratives/${id}`),
  disposition: (id: string, body: DispositionInput) =>
    api.patch<ThreatNarrative>(`/v1/narratives/${id}/disposition`, body),
};

// ───────────────────────────────────────── AI Guard (Phase 0/2.5)

export type AIGuardAction = "allow" | "block" | "detect";
export type AIGuardDirection = "inbound" | "outbound";
export type DetectorAction = "block" | "detect" | "off";

export type DetectorCatalog = {
  detectors: string[];
  default_thresholds: Record<string, number>;
};

export type DetectorOutcome = {
  name: string;
  category: string;
  confidence: number;
  threshold: number;
  triggered: boolean;
  action: string;
  severity: string;
  evidence: Record<string, unknown>;
};

export type AIGuardResponse = {
  action: AIGuardAction;
  direction: string;
  reason: string;
  triggered: string[];
  latency_ms: number;
  detectors: DetectorOutcome[];
  // Present when a block/detect verdict was published into the narrative
  // pipeline (the Phase 2.5 bridge).
  narrative?: { published: boolean; narrative_ids: string[] };
};

export type DetectorConfig = { threshold?: number; action?: DetectorAction };

export type InspectInput = {
  text: string;
  direction: AIGuardDirection;
  config: Record<string, DetectorConfig>;
  asset_id?: string;
  agent_instance_id?: string;
  correlation_key?: string;
  publish?: boolean;
};

export const aiguard = {
  detectors: () => api.get<DetectorCatalog>("/v1/aiguard/detectors"),
  inspect: (body: InspectInput) =>
    api.post<AIGuardResponse>("/v1/aiguard/inspect", body),
};

// ───────────────────────────────────────── Risk Index (Phase 2 SPM)

export type RiskComponents = {
  supply_chain_score: number;
  iam_over_privilege: number;
  runtime_block_rate: number;
  redteam_success_rate: number;
};

export type RiskIndexResult = {
  asset_id: string;
  score: number;
  grade: string;
  components: Record<string, number>;
};

export type RiskModel = {
  weights: Record<string, number>;
  grade_bands: Array<{ grade: string; min: number }>;
};

export const riskIndex = {
  model: () => api.get<RiskModel>("/v1/risk-index/model"),
  compute: (body: { asset_id: string } & RiskComponents) =>
    api.post<RiskIndexResult>("/v1/risk-index/compute", body),
};

// ───────────────────────────────────────── Model benchmark (Phase 4)

export type BenchmarkSeeds = {
  categories: Record<string, number>;
  total: number;
};

export type BenchmarkReport = {
  seeds: number;
  ranking: Array<{ model: string; resilience: number }>;
  models: Array<{
    model: string;
    best_resilience: number;
    configs: Array<{
      config: string;
      resilience: number;
      resisted: number;
      total: number;
    }>;
  }>;
};

export const benchmark = {
  seeds: () => api.get<BenchmarkSeeds>("/v1/benchmark/seeds"),
  run: (body: { system_prompts: Record<string, string>; categories?: string[] }) =>
    api.post<BenchmarkReport>("/v1/benchmark/run", body),
};

// ───────────────────────────────────────── Red Team (v2)

export type RedTeamStrategy = {
  id: string;
  category: string;
  name: string;
  description: string;
  severity: string;
  attack_type: string;
};

export type ConnectorSpecIn = {
  provider: string;
  model: string;
  api_key_ref?: string;
  config?: Record<string, unknown>;
};

export type CampaignCreate = {
  target: ConnectorSpecIn;
  system_prompt?: string;
  asset_description?: string;
  strategy_ids?: string[];
  max_attacks?: number | null;
};

export type RedTeamCampaign = {
  id: string;
  asset_id: string | null;
  status: string;
  total_attacks: number;
  successful_attacks: number;
  success_rate: number;
  target_errors: number;
  score: number;
  risk_label: string | null;
  total_cost_usd: number;
  summary: Record<string, unknown>;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
};

export type RedTeamFinding = {
  id: string;
  strategy_id: string;
  category: string;
  severity: string;
  classification: string;
  compliance_score: number;
  confidence: number;
  prompt: string;
  response: string;
  recommendation: string;
};

export const redteam = {
  strategies: () => api.get<RedTeamStrategy[]>("/v1/redteam/strategies"),
  listCampaigns: () => api.get<RedTeamCampaign[]>("/v1/redteam/campaigns"),
  getCampaign: (id: string) => api.get<RedTeamCampaign>(`/v1/redteam/campaigns/${id}`),
  createCampaign: (body: CampaignCreate) =>
    api.post<RedTeamCampaign>("/v1/redteam/campaigns", body),
  findings: (id: string) =>
    api.get<RedTeamFinding[]>(`/v1/redteam/campaigns/${id}/findings`),
};
