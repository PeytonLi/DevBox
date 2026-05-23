from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


def to_camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


class ApiModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProviderKind(StrEnum):
    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


class RiskProfile(StrEnum):
    CLOUD = "cloud"
    LOCAL = "local"


class CostTier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    LOCAL = "local"


class ScenarioCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    RAG_INJECTION = "rag_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"
    TOOL_MISUSE = "tool_misuse"
    UNSAFE_BROWSING = "unsafe_browsing"
    POLICY_BYPASS = "policy_bypass"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RunEventActor(StrEnum):
    SYSTEM = "system"
    ATTACKER = "attacker"
    TARGET_AGENT = "target_agent"
    SANDBOX = "sandbox"
    DEFENDER = "defender"


class PolicyDecision(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"


class DiffProviderMode(StrEnum):
    MANAGED_AGENT = "managed_agent"
    SIMULATOR = "simulator"


class DiffStatus(StrEnum):
    READY = "ready"
    PR_REQUESTED = "pr_requested"
    PR_CREATED = "pr_created"
    FAILED = "failed"


class SandboxPolicy(ApiModel):
    allowed_tools: list[str] = Field(default_factory=lambda: ["browser.open", "browser.read", "rag.search"])
    allowed_domains: list[str] = Field(default_factory=lambda: ["example.com", "docs.example.com"])
    filesystem_scope: str = "/workspace/agent"
    network_egress: Literal["allowlist"] = "allowlist"
    honeytokens: list[str] = Field(default_factory=lambda: ["DEVBOX_FAKE_SECRET", "sk-devbox-honeytoken"])


class AgentSpec(ApiModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=120)
    system_prompt: str = Field(min_length=20, max_length=8000)
    tools: list[str] = Field(default_factory=list)
    sandbox_policy: SandboxPolicy = Field(default_factory=SandboxPolicy)
    managed: bool = True


class ModelConfig(ApiModel):
    provider: ProviderKind
    model_id: str
    display_name: str
    enabled: bool
    unavailable_reason: str | None = None
    capabilities: list[str]
    privacy_note: str
    cost_tier: CostTier
    risk_profile: RiskProfile
    supports_tools: bool


class Scenario(ApiModel):
    id: str
    name: str
    category: ScenarioCategory
    setup_fixture: str
    attack_goal: str
    success_criteria: str
    expected_defense: str
    default_severity: Severity


class RunCreate(ApiModel):
    agent_id: str
    model_id: str
    scenario_ids: list[str] = Field(min_length=1)


class Run(ApiModel):
    id: str
    agent_id: str
    model_id: str
    scenario_ids: list[str]
    status: RunStatus = RunStatus.QUEUED
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    score: int | None = None


class RunEvent(ApiModel):
    sequence: int
    timestamp: datetime = Field(default_factory=utc_now)
    actor: RunEventActor
    message: str
    scenario_id: str | None = None
    tool_call: str | None = None
    policy_decision: PolicyDecision | None = None
    risk_signal: str | None = None


class Finding(ApiModel):
    id: str
    scenario_id: str
    severity: Severity
    violated_policy: str
    evidence: str
    recommendation: str


class PolicyDiff(ApiModel):
    id: str
    target: Literal["system_prompt", "sandbox_policy"]
    before: str
    after: str
    rationale: str


class Report(ApiModel):
    run_id: str
    score: int
    findings: list[Finding]
    trace_summary: str
    prompt_diff: PolicyDiff
    tool_policy_diff: PolicyDiff
    regression_tests: list[str]


class ApproveFixRequest(ApiModel):
    accepted_diff_ids: list[str]
    apply_to_agent: bool = True


class ApproveFixResponse(ApiModel):
    applied: bool
    agent: AgentSpec
    message: str


class HealthResponse(ApiModel):
    status: Literal["ok"]
    service: str
    version: str


class ToolRoute(ApiModel):
    requested_tools: list[str]
    observed_tools: list[str]
    violations: list[str]
    raw_step_count: int = 0


class DiffCreate(ApiModel):
    prompt: str = Field(min_length=20, max_length=12000)
    target_path: str | None = None
    use_managed_agent: bool = True
    allowed_tools: list[str] | None = None


class DiffResult(ApiModel):
    id: str
    provider_mode: DiffProviderMode
    status: DiffStatus
    prompt_before: str
    prompt_after: str
    unified_diff: str
    interaction_id: str | None = None
    environment_id: str | None = None
    tool_route: ToolRoute
    created_at: datetime = Field(default_factory=utc_now)
    target_path: str | None = None
    pr_url: str | None = None


class RequestPrResponse(DiffResult):
    branch: str | None = None
    commit_sha: str | None = None
