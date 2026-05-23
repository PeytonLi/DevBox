# DevBox AI Agent Security Lab

DevBox is an authorized security lab for testing managed or opt-in AI agents. It runs controlled attack scenarios in a sandbox, records traces, scores risk, and proposes system prompt or tool-policy fixes for approval.

## Stack

- `apps/web`: Next.js App Router dashboard.
- `services/api`: FastAPI orchestration API.
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

## Verification

```bash
pnpm typecheck
.venv\Scripts\python -m pytest services/api/tests
pnpm build
docker build -f infra/sandbox/Dockerfile .
```

## Safety Boundary

This project is built for authorized testing only. The MVP does not intercept unrelated third-party agents. It evaluates agents that are created in the lab or connected through explicit opt-in integrations.

## Docs

- `docs/SECURITY_MODEL.md`: sandbox and provider safety boundaries.
- `docs/FEATURE_HANDOFF.md`: reusable context packet for fresh agents building new features.
