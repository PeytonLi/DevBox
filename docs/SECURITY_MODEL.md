# Security Model

AgentSecure tests agents in an authorized sandbox. Local development can still use deterministic simulations, but the production pilot is designed for opt-in GitHub repository imports, persisted audit trails, and Gemini review after local redaction.

## Boundaries

- No stealth interception of third-party agents.
- Runs are scoped to managed or explicitly imported agents.
- Tool calls are checked against an allowlist before simulated execution.
- Honeytokens are fake secrets used only to validate exfiltration detection.
- Recommended prompt and policy changes require user approval before they are applied.
- GitHub imports are limited to explicitly selected repository paths.
- REST API calls in production require a server-side service token; browser traffic goes through the authenticated Next.js proxy.
- Run event streams require short-lived signed tokens.

## Sandbox Defaults

- Ephemeral execution context per run.
- Disposable browser profile.
- Scoped filesystem path.
- Network egress allowlist.
- Audit trail for every policy decision.
- Replayable trace events for reports and regression tests.

## Provider Defaults

Provider model entries are config-driven. Cloud providers are disabled until the related API key is present. Local models are disabled until a local runner URL is configured.

Gemini review receives locally redacted prompt content. Honeytokens, credential-shaped values, common PII patterns, and configured fake secrets are replaced before cloud review. If `DEVBOX_ENV=production` and a cloud review is requested without a Gemini key, the run fails instead of silently falling back.

## Diff-To-PR Boundary

- Prompt hardening uses a live Google Managed Agent only when `GEMINI_API_KEY` is configured; otherwise it uses the deterministic simulator.
- GitHub PR creation requires an explicit user action through `POST /v1/diffs/{diff_id}/request-pr`.
- FastAPI signs the internal PR webhook with `DEVBOX_PR_WEBHOOK_SECRET`; the Next.js Octokit route rejects missing or invalid signatures.
- PR output writes only the approved prompt diff to the configured target path and does not include private prompts beyond the approved file contents.
- PR descriptions intentionally omit prompt body/diff content; approved prompt content is committed to the branch file only.
