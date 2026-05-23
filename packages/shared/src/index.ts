export type ProviderKind = "google" | "openai" | "anthropic" | "local";
export type RiskProfile = "cloud" | "local";
export type CostTier = "low" | "medium" | "high" | "local";
export type ScenarioCategory =
  | "prompt_injection"
  | "rag_injection"
  | "secret_exfiltration"
  | "tool_misuse"
  | "unsafe_browsing"
  | "policy_bypass";
export type RunStatus = "queued" | "running" | "completed" | "failed";
export type Severity = "low" | "medium" | "high" | "critical";
export type RunEventActor = "system" | "attacker" | "target_agent" | "sandbox" | "defender";
export type PolicyDecision = "allowed" | "blocked" | "flagged";
export type DiffProviderMode = "managed_agent" | "simulator";
export type DiffStatus = "ready" | "pr_requested" | "pr_created" | "failed";

export interface SandboxPolicy {
  allowedTools: string[];
  allowedDomains: string[];
  filesystemScope: string;
  networkEgress: "allowlist";
  honeytokens: string[];
}

export interface AgentSpec {
  id?: string;
  name: string;
  systemPrompt: string;
  tools: string[];
  sandboxPolicy: SandboxPolicy;
  managed: boolean;
}

export interface ModelConfig {
  provider: ProviderKind;
  modelId: string;
  displayName: string;
  enabled: boolean;
  unavailableReason?: string | null;
  capabilities: string[];
  privacyNote: string;
  costTier: CostTier;
  riskProfile: RiskProfile;
  supportsTools: boolean;
}

export interface Scenario {
  id: string;
  name: string;
  category: ScenarioCategory;
  setupFixture: string;
  attackGoal: string;
  successCriteria: string;
  expectedDefense: string;
  defaultSeverity: Severity;
}

export interface Run {
  id: string;
  agentId: string;
  modelId: string;
  scenarioIds: string[];
  status: RunStatus;
  createdAt: string;
  completedAt?: string | null;
  score?: number | null;
}

export interface RunCreate {
  agentId: string;
  modelId: string;
  scenarioIds: string[];
}

export interface RunEvent {
  sequence: number;
  timestamp: string;
  actor: RunEventActor;
  message: string;
  scenarioId?: string | null;
  toolCall?: string | null;
  policyDecision?: PolicyDecision | null;
  riskSignal?: string | null;
}

export interface Finding {
  id: string;
  scenarioId: string;
  severity: Severity;
  violatedPolicy: string;
  evidence: string;
  recommendation: string;
}

export interface PolicyDiff {
  id: string;
  target: "system_prompt" | "sandbox_policy";
  before: string;
  after: string;
  rationale: string;
}

export interface Report {
  runId: string;
  score: number;
  findings: Finding[];
  traceSummary: string;
  promptDiff: PolicyDiff;
  toolPolicyDiff: PolicyDiff;
  regressionTests: string[];
}

export interface ApproveFixRequest {
  acceptedDiffIds: string[];
  applyToAgent: boolean;
}

export interface ApproveFixResponse {
  applied: boolean;
  agent: AgentSpec;
  message: string;
}

export interface ToolRoute {
  requestedTools: string[];
  observedTools: string[];
  violations: string[];
  rawStepCount: number;
}

export interface DiffCreate {
  prompt: string;
  targetPath?: string | null;
  useManagedAgent: boolean;
  allowedTools?: string[] | null;
}

export interface DiffResult {
  id: string;
  providerMode: DiffProviderMode;
  status: DiffStatus;
  promptBefore: string;
  promptAfter: string;
  unifiedDiff: string;
  interactionId?: string | null;
  environmentId?: string | null;
  toolRoute: ToolRoute;
  createdAt: string;
  targetPath?: string | null;
  prUrl?: string | null;
}

export interface RequestPrResponse extends DiffResult {
  branch?: string | null;
  commitSha?: string | null;
}
