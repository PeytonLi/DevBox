import type {
  AgentProjectImportResponse,
  AgentImportRecord,
  AgentSpec,
  AdminSessionResponse,
  ApproveFixRequest,
  ApproveFixResponse,
  DiffCreate,
  DiffResult,
  EventsTokenResponse,
  GitHubImportSource,
  ModelConfig,
  Report,
  RepositoryRecord,
  RequestPrResponse,
  Run,
  RunCreate,
  Scenario,
  TargetAgentTemplate
} from "@devbox/shared";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? (process.env.NODE_ENV === "production" ? "/api/devbox" : "http://localhost:8000");
const API_WS_BASE_URL =
  process.env.NEXT_PUBLIC_API_WS_BASE_URL ??
  process.env.NEXT_PUBLIC_API_DIRECT_BASE_URL ??
  (API_BASE_URL.startsWith("http") ? API_BASE_URL : "http://localhost:8000");

async function request<T>(path: string, init?: RequestInit & { baseUrl?: string }): Promise<T> {
  const isFormData = typeof FormData !== "undefined" && init?.body instanceof FormData;
  const { baseUrl, ...requestInit } = init ?? {};
  const response = await fetch(`${baseUrl ?? API_BASE_URL}${path}`, {
    ...requestInit,
    headers: isFormData
      ? requestInit.headers
      : {
          "Content-Type": "application/json",
          ...(requestInit.headers ?? {})
        }
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {
      // Keep the response status text when the API did not return JSON.
    }
    throw new Error(detail);
  }

  return (await response.json()) as T;
}

export const api = {
  getSession: () => request<AdminSessionResponse>("/api/auth/session", { baseUrl: "" }),
  listModels: () => request<ModelConfig[]>("/v1/models"),
  listScenarios: () => request<Scenario[]>("/v1/scenarios"),
  listTargetAgents: () => request<TargetAgentTemplate[]>("/v1/target-agents"),
  listRepositories: () => request<RepositoryRecord[]>("/v1/repositories"),
  importGitHubAgent: (source: GitHubImportSource) =>
    request<AgentImportRecord>("/v1/github/imports", {
      method: "POST",
      body: JSON.stringify(source)
    }),
  registerTargetAgent: (targetAgentId: string) =>
    request<AgentSpec>(`/v1/target-agents/${targetAgentId}/register`, {
      method: "POST"
    }),
  importAgentProject: (manifest: File, promptFile?: File | null) => {
    const body = new FormData();
    body.append("manifest", manifest);
    if (promptFile) {
      body.append("promptFile", promptFile);
    }
    return request<AgentProjectImportResponse>("/v1/agent-projects/import", {
      method: "POST",
      body
    });
  },
  createAgent: (agent: AgentSpec) =>
    request<AgentSpec>("/v1/agents", {
      method: "POST",
      body: JSON.stringify(agent)
    }),
  createRun: (run: RunCreate) =>
    request<Run>("/v1/runs", {
      method: "POST",
      body: JSON.stringify(run)
    }),
  getRun: (runId: string) => request<Run>(`/v1/runs/${runId}`),
  getReport: (runId: string) => request<Report>(`/v1/runs/${runId}/report`),
  getRunEventsToken: (runId: string) => request<EventsTokenResponse>(`/v1/runs/${runId}/events-token`),
  approveFix: (runId: string, payload: ApproveFixRequest) =>
    request<ApproveFixResponse>(`/v1/runs/${runId}/approve-fix`, {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  approveRunPr: (runId: string, payload?: ApproveFixRequest) =>
    request<RequestPrResponse>(`/v1/runs/${runId}/approve-pr`, {
      method: "POST",
      body: payload ? JSON.stringify(payload) : undefined
    }),
  createDiff: (payload: DiffCreate) =>
    request<DiffResult>("/v1/diffs", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  requestPr: (diffId: string) =>
    request<RequestPrResponse>(`/v1/diffs/${diffId}/request-pr`, {
      method: "POST"
    }),
  toolRoutingSmoke: (payload: DiffCreate) =>
    request<DiffResult>("/v1/managed-agent/tool-routing-smoke", {
      method: "POST",
      body: JSON.stringify(payload)
    })
};

export function webSocketUrl(path: string) {
  const url = new URL(API_WS_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = path;
  return url.toString();
}
