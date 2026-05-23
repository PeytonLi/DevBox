# Security Model

DevBox tests agents in an authorized sandbox. The MVP uses deterministic simulations so teams can validate the workflow before connecting real providers or customer agents.

## Boundaries

- No stealth interception of third-party agents.
- Runs are scoped to managed or explicitly imported agents.
- Tool calls are checked against an allowlist before simulated execution.
- Honeytokens are fake secrets used only to validate exfiltration detection.
- Recommended prompt and policy changes require user approval before they are applied.

## Sandbox Defaults

- Ephemeral execution context per run.
- Disposable browser profile.
- Scoped filesystem path.
- Network egress allowlist.
- Audit trail for every policy decision.
- Replayable trace events for reports and regression tests.

## Provider Defaults

Provider model entries are config-driven. Cloud providers are disabled until the related API key is present. Local models are disabled until a local runner URL is configured.
