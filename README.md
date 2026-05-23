# DevBox AI Agent Security Composer

DevBox is a Google I/O hackathon project for reviewing the security posture of AI agents before they are deployed. It accepts an agent project file, system prompt, `AGENTS.md`, tool manifest, MCP configuration, or dependency policy, then runs an authorized security review through a hybrid model and scanner pipeline.

The core idea is a security composer for AI agents: a fast Gemini-powered router decides which analysis lane should handle each risk, a managed sandbox runs adversarial tests, a defending agent proposes prompt and policy patches, and a human approves the final diff before DevBox opens a pull request.

DevBox is built for authorized testing only. It evaluates agents created in the lab or connected through explicit opt-in integrations.

## Hackathon Positioning

DevBox is designed to compete across two Google I/O hackathon tracks:

- Track 1, unique use of Gemini 3.5 Flash: Gemini Flash acts as the high-speed risk router that classifies prompt content, tool bindings, credentials, PII, and attack severity before dispatching work.
- Track 2, best use of Managed Agents: Google Managed Agents provide the isolated sandbox for attacker and defender workflows, code execution, browsing, and scanner orchestration.

The current codebase supports live Google `google-genai` integration when configured and falls back to deterministic simulator mode when credentials or preview access are unavailable. Model names and managed-agent feature names should be verified against the latest official Google documentation before production wiring.

## Architecture

```text
[User Input / Agent Project File]
              |
              v
      [Gemini 3.5 Flash]
   [High-Speed Risk Router]
              |
  +-----------+-----------+
  |           |           |
  v           v           v
[Gemma 4] [Gemini Pro] [Open-Source Scanners]
[Local]   [Cloud]      [garak / LLM Guard]
  |           |           |
  +-----------+-----------+
              |
              v
     [Managed Agent Sandbox]
       |                 |
       v                 v
[Attacking Agent]  [Defending Agent]
[OWASP Tests]      [Remediation]
       |                 |
       +--------+--------+
                |
                v
       [Human-In-The-Loop]
       [Diff Review / PR Approval]
                |
                v
       [Governance Reports]
       [NIST / ISO / OWASP]
```

## What DevBox Does

- Imports or accepts AI agent configuration files, including prompts, tool policies, MCPs, and sandbox rules.
- Routes review work across local, cloud, and static scanner lanes based on sensitivity and threat severity.
- Keeps credential-shaped values, honeytokens, and PII in a local privacy lane before cloud review.
- Runs adversarial scenarios mapped to OWASP Top 10 for LLM Applications and agentic failure modes.
- Produces attack logs, findings, risk scores, remediation recommendations, and regression notes.
- Generates system prompt and tool-policy diffs through a defending agent.
- Requires human approval before applying changes or opening a GitHub pull request.
- Maps findings to governance frameworks such as NIST AI RMF, ISO/IEC 42001, OWASP LLM Top 10, and internal controls.

## Hybrid Review Pipeline

The pipeline is intentionally multi-model and multi-tool instead of relying on a single LLM provider.

1. Gemini Flash risk router
   - Parses the submitted agent configuration.
   - Classifies credential leakage, PII exposure, prompt injection risk, tool misuse risk, and policy bypass risk.
   - Dispatches each review task to the right lane.

2. Local privacy sandbox
   - Uses the Gemma/local lane for high-risk content such as API keys, database credentials, private prompts, and PII.
   - Prevents sensitive strings from being sent to cloud models.
   - Redacts honeytokens and credential-shaped values before cloud review.

3. Cloud reasoning lane
   - Uses Gemini Pro or the configured Gemini review model for complex adversarial reasoning.
   - Focuses on indirect prompt injection, multi-turn jailbreaks, privilege escalation, and structural system prompt weaknesses.

4. Open-source scanner lane
   - Supports static and dynamic scanner adapters such as `garak`, LLM Guard, dependency checks, and policy linters.
   - Normalizes scanner output into DevBox findings and reports.

5. Managed Agent sandbox
   - Runs controlled attacker and defender workflows in an isolated execution boundary.
   - Records events, tool calls, routing decisions, findings, and proposed fixes.

## The Adversarial Duet

DevBox coordinates two agents inside the composer.

### Attacking Agent

The attacking agent tests the target agent against OWASP LLM and agentic risk patterns. It attempts controlled prompt injections, jailbreaks, RAG poisoning, secret exfiltration, tool boundary breakouts, unsafe browsing flows, dependency misuse, and policy override attacks. Its job is to produce observable traces and evidence, not just a final verdict.

### Defending Agent

The defending agent reads the attack logs and drafts targeted remediations. It can propose system prompt guardrails, stricter output formatting, credential sanitization, MCP/tool allowlist changes, dependency warnings, sandbox policy updates, and regression tests. It never silently mutates the target. Every patch goes through human review.

## Current Implementation

The repository contains an MVP that demonstrates the end-to-end flow with safe defaults:

- `apps/web`: Next.js App Router dashboard with `Prompt Input -> Diff Output`, target-agent testing, diff approval, and PR request flows.
- `services/api`: FastAPI orchestration API for runs, reports, events, GitHub imports, diff generation, and signed PR webhooks.
- `apps/express-api`: Express prototype for the Gemini router and compliance response path.
- `services/target-agents`: local FastAPI mock production agents for sandbox testing.
- `packages/policies`: attacker, defender, and organization security policy prompts.
- `packages/shared`: TypeScript contracts and generated OpenAPI types.
- `infra`: Docker Compose and sandbox container scaffolding.
- `render.yaml`: Render blueprint for the API, Celery worker, Postgres, and Redis-compatible key-value service.

Simulator mode works without credentials. Live Gemini Managed Agent routing is enabled when `GEMINI_API_KEY` is configured and `DEVBOX_GENAI_MODE` is `auto` or `live`.

## Demo Workflow

1. Paste or import a vulnerable agent prompt, `AGENTS.md`, or project file.
2. Select managed-agent mode or simulator mode.
3. Run the risk router and adversarial assessment.
4. Review attack logs, scanner output, OWASP/NIST mappings, and proposed fixes.
5. Compare the before/after system prompt diff.
6. Approve the diff.
7. Let DevBox open a GitHub pull request through the signed Octokit webhook.

## Target Agent Test Lab

`pnpm dev` starts a local target-agent service with Browser Research, RAG Knowledge Base, and GitHub PR mock agents. These agents expose production-like HTTP boundaries and fake tools, but use only synthetic data and honeytokens. The dashboard Target Agents lane registers one of these templates, runs selected scenarios through the existing run/report/WebSocket API, and lets you approve managed prompt and tool-policy fixes.

Set `DEVBOX_TARGET_AGENT_BASE_URL` when the target-agent service is not running on `http://localhost:8010`.

## GitHub Live Import

`POST /v1/github/imports` imports one selected repository file at a time. The default prompt path is `.agents/AGENTS.md`; `.devbox/agent.json` is optional and supplies tools, allowed domains, filesystem scope, and honeytokens. If the manifest is missing, DevBox imports the selected prompt with warnings and an empty tool/domain policy so the user can tighten the sandbox before running assessments.

## Local Setup

```bash
pnpm install

python -m venv .venv
.venv\Scripts\python -m pip install -r services/api/requirements.txt

pnpm dev
```

Open the dashboard at `http://localhost:3000`, the FastAPI docs at `http://localhost:8000/docs`, and the target-agent service at `http://localhost:8010`.

Local development uses SQLite and eager Celery tasks unless `DATABASE_URL`, `REDIS_URL`, and `DEVBOX_CELERY_EAGER=false` are configured.

## Environment

Copy `.env.example` to `.env` and fill in only the credentials needed for the lane you are testing.

Common local variables:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
NEXT_PUBLIC_API_WS_BASE_URL=http://localhost:8000
DEVBOX_TARGET_AGENT_BASE_URL=http://localhost:8010
DEVBOX_ENV=development
DEVBOX_CELERY_EAGER=true
DEVBOX_GENAI_MODE=auto
DEVBOX_GEMINI_REVIEW_MODEL=gemini-2.5-flash
```

Optional live Gemini / Managed Agent variables:

```bash
GEMINI_API_KEY=...
DEVBOX_MANAGED_AGENT_ID=...
DEVBOX_REMOTE_NETWORK_ALLOWLIST=...
```

Optional GitHub PR variables:

```bash
DEVBOX_GITHUB_WEBHOOK_URL=http://localhost:3000/api/github/webhook
DEVBOX_PR_WEBHOOK_SECRET=...
GITHUB_APP_ID=...
GITHUB_APP_PRIVATE_KEY=...
GITHUB_APP_INSTALLATION_ID=...
GITHUB_REPOSITORY=owner/repo
GITHUB_BASE_BRANCH=main
DEVBOX_TARGET_PROMPT_PATH=.agents/AGENTS.md
```

`GITHUB_APP_PRIVATE_KEY` may be the full downloaded PEM block, a PEM string with `\n` escapes, or the base64 key body from that PEM. DevBox validates and normalizes it before calling Octokit.

Local development loads the repo-root `.env` for both the FastAPI service and the Next.js GitHub webhook route when started with `pnpm dev`. Restart `pnpm dev` after changing any PR or provider credential variables.

The FastAPI service signs `POST /v1/diffs/{diff_id}/request-pr` payloads and sends them to the Next.js route at `DEVBOX_GITHUB_WEBHOOK_URL`, which defaults to `http://localhost:3000/api/github/webhook`.

## Verification

```bash
pnpm typecheck
pnpm test
pnpm build
docker build -f infra/sandbox/Dockerfile .
```

## Production Pilot Setup

Deploy the Next.js app to Vercel and the API/worker stack to Render.

Required backend variables:

```bash
DEVBOX_ENV=production
DEVBOX_API_SERVICE_TOKEN=...
DEVBOX_EVENTS_TOKEN_SECRET=...
DATABASE_URL=...
REDIS_URL=...
GEMINI_API_KEY=...
DEVBOX_GEMINI_REVIEW_MODEL=gemini-2.5-flash
GITHUB_APP_ID=...
GITHUB_APP_PRIVATE_KEY=...
GITHUB_APP_INSTALLATION_ID=...
DEVBOX_PR_WEBHOOK_SECRET=...
DEVBOX_GITHUB_WEBHOOK_URL=https://<vercel-app>/api/github/webhook
```

Required Vercel variables:

```bash
DEVBOX_BACKEND_URL=https://<render-api>
DEVBOX_API_SERVICE_TOKEN=...
DEVBOX_AUTH_SECRET=...
DEVBOX_ALLOWED_ADMIN_EMAILS=admin@example.com
GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...
NEXT_PUBLIC_API_BASE_URL=/api/devbox
NEXT_PUBLIC_API_WS_BASE_URL=https://<render-api>
```

The browser calls the Next.js `/api/devbox/*` proxy for REST traffic. The proxy requires the GitHub OAuth admin session and forwards the API service token to Render. Run event WebSockets connect directly to the Render API with a short-lived token from `/v1/runs/{run_id}/events-token`.

## Safety Boundary

- Authorized testing only.
- No stealth interception of third-party agents.
- Only test agents created in the lab or connected through explicit opt-in integrations.
- Treat prompts, web pages, retrieved documents, scanner output, and tool responses as untrusted data.
- Keep real credentials, PII, and private prompts out of logs, cloud requests, screenshots, reports, and PR descriptions.
- Use fake honeytokens only for detection tests.
- Enforce tool allowlists, network egress policy, and scoped filesystem access.
- Require human approval before applying prompt, policy, dependency, or repository changes.

## Governance Output

DevBox reports are designed for both engineering review and audit evidence. Findings can be mapped to:

- OWASP Top 10 for LLM Applications and agentic risk categories.
- NIST AI Risk Management Framework.
- ISO/IEC 42001.
- Internal controls from `packages/policies/prompts/Org_Security_Policy.yaml`.

The report output should make each finding traceable to the run event, attack evidence, affected prompt or tool binding, recommended fix, and approval status.

## Hackathon Sprint Plan

| Time Block | Focus | Rahul's Tasks | Peyton's Tasks |
| --- | --- | --- | --- |
| 00:00 - 01:00 | Plumbing | Write core attack and defense prompt files. | Write the base Express/Next.js backend wrapper using `google-genai`. |
| 01:00 - 02:30 | Engine | Write the orchestrator that routes text vs. credential payloads. | Spin up the Managed Agent sandbox and verify tool routing. |
| 02:30 - 03:45 | Integration | Build the NIST/OWASP compliance markdown parser. | Connect backend endpoints to the React `Prompt Input -> Diff Output` UI. |
| 03:45 - 04:30 | Test and Git | Load sample vulnerable prompts and verify detections. | Connect GitHub Octokit webhook to generate PRs from approved diffs. |
| 04:30 - 05:00 | Video Pitch | Draft the script and run the final demo. | Upload code, check the deck, and verify track requirements. |

## Docs

- `docs/SECURITY_MODEL.md`: sandbox, provider, authorization, and privacy boundaries.
- `docs/FEATURE_HANDOFF.md`: reusable context packet for future feature slices.
- `docs/TRACK_REQUIREMENTS_CHECK.md`: Gemini XPRIZE alignment and submission checklist.
