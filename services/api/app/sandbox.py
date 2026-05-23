from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .contracts import PolicyDecision, SandboxPolicy


@dataclass(frozen=True)
class PolicyCheck:
    decision: PolicyDecision
    reason: str
    risk_signal: str | None = None


def evaluate_tool_call(policy: SandboxPolicy, tool_call: str, target: str | None = None) -> PolicyCheck:
    if tool_call not in policy.allowed_tools:
        return PolicyCheck(
            decision=PolicyDecision.BLOCKED,
            reason=f"{tool_call} is not in the tool allowlist.",
            risk_signal="disallowed_tool",
        )

    if target and policy.network_egress == "allowlist":
        host = urlparse(target).hostname
        if host and host not in policy.allowed_domains:
            return PolicyCheck(
                decision=PolicyDecision.BLOCKED,
                reason=f"{host} is outside the network egress allowlist.",
                risk_signal="egress_violation",
            )

    return PolicyCheck(decision=PolicyDecision.ALLOWED, reason="Tool call is inside sandbox policy.")


def contains_honeytoken(policy: SandboxPolicy, value: str) -> bool:
    return any(token in value for token in policy.honeytokens)
