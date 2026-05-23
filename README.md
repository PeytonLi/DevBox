# DevBox AI Agent Security Composer

DevBox is a security review system for AI agents. It analyzes agent prompts, tool bindings, MCP configurations, dependency policies, and project files before those agents are deployed.

The project was designed for the Google I/O hackathon around a hybrid Gemini/Gemma architecture: use fast cloud models for routing and reasoning, local models for sensitive data, managed sandboxes for controlled execution, and human approval before any remediation is applied.

## Problem

AI agents are increasingly defined by system prompts, connected tools, MCP servers, dependencies, browsing permissions, and repository access. That creates a new security review problem:

- Prompt injection can override the agent's intended behavior.
- Tool access can expand an agent's blast radius.
- Agent prompts may contain credentials, PII, or sensitive business logic.
- MCP and dependency configuration can introduce unsafe capabilities.
- Security teams need audit evidence, not just a model-generated opinion.
- Single-provider scanners create blind spots because one model is judging another agent's behavior alone.

DevBox treats AI agent security as an adversarial, multi-model review workflow rather than a static prompt linting task.

## Solution

DevBox is a hybrid AI agent security composer. It routes each part of an agent review to the best available model or scanner, runs attacks in a controlled sandbox, generates defensive fixes, and keeps a human in the approval loop.

The system combines:

- A Gemini Flash risk router for fast severity and sensitivity classification.
- A local Gemma-style privacy lane for credentials, PII, honeytokens, and private prompts.
- A stronger Gemini cloud reasoning lane for complex prompt injection and adversarial analysis.
- Open-source scanners such as `garak`, LLM Guard, dependency checkers, and policy linters.
- A managed sandbox for controlled attacker and defender agent execution.
- A governance layer that maps findings to OWASP LLM Top 10, NIST AI RMF, ISO/IEC 42001, and internal policy controls.

## Architecture

```text
[Agent Prompt / AGENTS.md / MCP Config / Tool Policy]
                         |
                         v
              [Gemini Flash Risk Router]
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
[Local Gemma Lane] [Gemini Reasoning] [Open-Source Scanners]
[Secrets + PII]    [Injection + Logic] [garak / LLM Guard]
        |                |                |
        +----------------+----------------+
                         |
                         v
              [Managed Agent Sandbox]
              |                       |
              v                       v
      [Attacking Agent]       [Defending Agent]
      [OWASP Scenarios]       [Prompt + Policy Fixes]
              |                       |
              +-----------+-----------+
                          |
                          v
               [Human Review + Diff Approval]
                          |
                          v
              [Pull Request + Audit Report]
```

## Core Workflow

1. Import or paste an AI agent configuration.
2. Route sensitive content, prompt logic, and scanner tasks through the appropriate review lane.
3. Run adversarial tests against the target agent in a managed sandbox.
4. Record traces, tool calls, findings, and severity scores.
5. Let the defending agent draft targeted prompt and policy fixes.
6. Show the proposed changes as a human-reviewable diff.
7. After approval, open a pull request and generate a compliance-oriented report.

## Adversarial Duet

DevBox uses two coordinated agents during review.

### Attacking Agent

The attacking agent tests the target against OWASP LLM and agentic risk patterns. It attempts controlled prompt injection, jailbreaks, RAG poisoning, secret exfiltration, unsafe browsing, tool boundary breakout, dependency misuse, and policy override attacks.

Its output is evidence: attack traces, exploited assumptions, tool calls, leaked tokens, violated policy rules, and mapped risk categories.

### Defending Agent

The defending agent reads the attack evidence and proposes remediations. It can draft:

- System prompt hardening.
- Tool and MCP allowlist changes.
- Credential and PII handling rules.
- Output formatting constraints.
- Sandbox policy updates.
- Regression tests for discovered failures.
- Governance mappings for audit review.

The defending agent does not silently mutate the target agent. Every change requires human approval.

## Current Prototype

The MVP demonstrates the end-to-end concept with safe defaults:

- `apps/web`: Next.js App Router dashboard for prompt input, scenario runs, findings, and diff review.
- `services/api`: FastAPI orchestration service for runs, reports, event streams, GitHub imports, and signed PR requests.
- `services/target-agents`: local FastAPI mock production agents for sandbox testing of browser, RAG, and GitHub PR-style workflows.
- `infra/policies`: shared scenario metadata for frontend/package consumers (`@devbox/policies`).
- `infra`: Docker Compose and sandbox container.
- `render.yaml`: Render blueprint for FastAPI web service, Celery worker, Postgres, and Render Key Value.
- Shared attacker, defender, and organization security policy prompts.
- Simulator mode when live Gemini Managed Agent access is not configured.

## Security Boundary

DevBox is for authorized security testing only. It evaluates agents created in the lab or connected through explicit opt-in integrations.

Sensitive content is routed through local redaction and privacy-preserving lanes before cloud review. Prompt, policy, dependency, and repository changes require human approval before they are applied.
