# DevBox AI Agent Security Lab

DevBox is an authorized security lab for testing managed or opt-in AI agents. It runs controlled attack scenarios in a sandbox, records traces, scores risk, and proposes system prompt or tool-policy fixes for approval.

The current dashboard also includes a focused `Prompt Input -> Diff Output` flow. It uses Google Managed Agents through `google-genai` when configured, falls back to the local simulator when not configured, verifies tool routing, and can open a GitHub PR from an approved prompt diff through a signed Next.js Octokit webhook.

## Stack

- `apps/web`: Next.js App Router dashboard.
- `services/api`: FastAPI orchestration API.
- `services/target-agents`: local FastAPI mock production agents for sandbox testing.
- `packages/shared`: TypeScript contracts and generated OpenAPI types.
- `packages/policies`: shared scenario metadata for frontend/package consumers.
- `infra`: Docker Compose and sandbox container.

## Local Setup

```bash
pnpm install

python -m venv .venv
.venv\Scripts\python -m pip install -r services/api/requirements.txt

pnpm dev
```

Open the dashboard at `http://localhost:3000` and the API docs at `http://localhost:8000/docs`.
The target-agent service runs at `http://localhost:8010`.

## Verification

```bash
pnpm typecheck
pnpm test
pnpm build
docker build -f infra/sandbox/Dockerfile .
```

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
