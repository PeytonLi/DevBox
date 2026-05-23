# DevBox AI Agent Security Lab

DevBox is an authorized security lab for testing managed or opt-in AI agents. It runs controlled attack scenarios in a sandbox, records traces, scores risk, and proposes system prompt or tool-policy fixes for approval.

The current dashboard also includes a focused `Prompt Input -> Diff Output` flow. It uses Google Managed Agents through `google-genai` when configured, falls back to the local simulator when not configured, verifies tool routing, and can open a GitHub PR from an approved prompt diff through a signed Next.js Octokit webhook.

The production pilot path is GitHub-first: an allowlisted admin imports an explicitly selected repo file, DevBox stores the agent/run/report data in Postgres, dispatches assessments through Celery/Redis, runs local redaction before Gemini review, streams persisted events with short-lived tokens, and creates remediation PRs only after approval.

## Stack

- `apps/web`: Next.js App Router dashboard.
- `services/api`: FastAPI orchestration API.
- `services/target-agents`: local FastAPI mock production agents for sandbox testing.
- `packages/shared`: TypeScript contracts and generated OpenAPI types.
- `packages/policies`: shared scenario metadata for frontend/package consumers.
- `infra`: Docker Compose and sandbox container.
- `render.yaml`: Render blueprint for FastAPI web service, Celery worker, Postgres, and Render Key Value.

## Local Setup

```bash
pnpm install

python -m venv .venv
.venv\Scripts\python -m pip install -r services/api/requirements.txt

pnpm dev
```

Open the dashboard at `http://localhost:3000` and the API docs at `http://localhost:8000/docs`.
The target-agent service runs at `http://localhost:8010`.

Local development uses SQLite and eager Celery tasks unless `DATABASE_URL`, `REDIS_URL`, and `DEVBOX_CELERY_EAGER=false` are configured.

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

This project is built for authorized testing only. The MVP does not intercept unrelated third-party agents. It evaluates agents that are created in the lab or connected through explicit opt-in integrations.

## Docs

- `docs/SECURITY_MODEL.md`: sandbox and provider safety boundaries.
- `docs/FEATURE_HANDOFF.md`: reusable context packet for fresh agents building new features.
- `docs/TRACK_REQUIREMENTS_CHECK.md`: Build with Gemini XPRIZE alignment and deck-review checklist.

## Managed Agent Diff-to-PR Setup

Simulator mode works without credentials. For live Gemini Managed Agent routing, set `GEMINI_API_KEY` and keep `DEVBOX_GENAI_MODE=auto` or set `DEVBOX_GENAI_MODE=live`.

Local development loads the repo-root `.env` for both the FastAPI service and the Next.js GitHub webhook route when started with `pnpm dev`. Restart `pnpm dev` after changing any PR or provider credential variables.

For GitHub PR creation, configure:

```bash
DEVBOX_PR_WEBHOOK_SECRET=...
GITHUB_APP_ID=...
GITHUB_APP_PRIVATE_KEY=...
GITHUB_APP_INSTALLATION_ID=...
GITHUB_REPOSITORY=PeytonLi/DevBox
```

`GITHUB_APP_PRIVATE_KEY` may be the full downloaded PEM block, a PEM string with `\n` escapes, or the base64 key body from that PEM. DevBox validates and normalizes it before calling Octokit.

The FastAPI service signs `POST /v1/diffs/{diff_id}/request-pr` payloads and sends them to the Next.js route at `DEVBOX_GITHUB_WEBHOOK_URL`, which defaults to `http://localhost:3000/api/github/webhook`.

## Target Agent Test Lab

`pnpm dev` also starts a local target-agent service with Browser Research, RAG Knowledge Base, and GitHub PR mock agents. These agents expose production-like HTTP boundaries and fake tools, but use only synthetic data and honeytokens. The dashboard Target Agents lane registers one of these templates, runs selected scenarios through the existing run/report/WebSocket API, and lets you approve managed prompt and tool-policy fixes.

Set `DEVBOX_TARGET_AGENT_BASE_URL` when the target-agent service is not running on `http://localhost:8010`.

## GitHub Live Import

`POST /v1/github/imports` imports one selected repository file at a time. The default prompt path is `.agents/AGENTS.md`; `.devbox/agent.json` is optional and supplies tools, allowed domains, filesystem scope, and honeytokens. If the manifest is missing, DevBox imports the selected prompt with warnings and an empty tool/domain policy so the user can tighten the sandbox before running assessments.
