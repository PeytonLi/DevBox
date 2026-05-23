import type {
  AgentSpec,
  ApproveFixRequest,
  ApproveFixResponse,
  ModelConfig,
  Report,
  Run,
  RunCreate,
  Scenario
} from "@devbox/shared";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
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
  listModels: () => request<ModelConfig[]>("/v1/models"),
  listScenarios: () => request<Scenario[]>("/v1/scenarios"),
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
  approveFix: (runId: string, payload: ApproveFixRequest) =>
    request<ApproveFixResponse>(`/v1/runs/${runId}/approve-fix`, {
      method: "POST",
      body: JSON.stringify(payload)
    })
};

export function webSocketUrl(path: string) {
  const url = new URL(API_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = path;
  return url.toString();
}
