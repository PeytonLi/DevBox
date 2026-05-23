from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from .contracts import DiffCreate, DiffResult, DiffStatus, RequestPrResponse
from .managed_agents import ManagedAgentClient


DEFAULT_TARGET_PATH = ".agents/AGENTS.md"
DEFAULT_WEBHOOK_URL = "http://localhost:3000/api/github/webhook"


class DiffManagerError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class GitHubWebhookResult:
    pr_url: str
    branch: str | None = None
    commit_sha: str | None = None


class DiffManager:
    def __init__(self, managed_agents: ManagedAgentClient) -> None:
        self.managed_agents = managed_agents
        self.diffs: dict[str, DiffResult] = {}

    async def create_diff(self, payload: DiffCreate) -> DiffResult:
        output = self.managed_agents.generate_prompt_diff(
            prompt=payload.prompt,
            target_path=payload.target_path,
            use_managed_agent=payload.use_managed_agent,
            allowed_tools=payload.allowed_tools,
        )
        target_path = payload.target_path or DEFAULT_TARGET_PATH
        diff = DiffResult(
            id=f"diff_{uuid.uuid4().hex[:10]}",
            provider_mode=output.provider_mode,
            status=DiffStatus.READY,
            prompt_before=payload.prompt,
            prompt_after=output.prompt_after,
            unified_diff=unified_prompt_diff(payload.prompt, output.prompt_after, target_path),
            interaction_id=output.interaction_id,
            environment_id=output.environment_id,
            tool_route=output.tool_route,
            target_path=target_path,
        )
        self.diffs[diff.id] = diff
        return diff

    def get_diff(self, diff_id: str) -> DiffResult | None:
        return self.diffs.get(diff_id)

    async def request_pr(self, diff_id: str) -> RequestPrResponse:
        diff = self.diffs.get(diff_id)
        if diff is None:
            raise DiffManagerError(404, "Diff not found.")
        if diff.status not in {DiffStatus.READY, DiffStatus.PR_REQUESTED, DiffStatus.PR_CREATED}:
            raise DiffManagerError(409, "Diff is not ready for PR creation.")
        if diff.pr_url:
            return RequestPrResponse(**diff.model_dump(), branch=None, commit_sha=None)

        webhook_url = os.getenv("DEVBOX_GITHUB_WEBHOOK_URL", DEFAULT_WEBHOOK_URL).strip()
        webhook_secret = os.getenv("DEVBOX_PR_WEBHOOK_SECRET", "").strip()
        if not webhook_url or not webhook_secret:
            raise DiffManagerError(503, "GitHub PR creation unavailable: webhook URL or secret is not configured.")

        requested = diff.model_copy(update={"status": DiffStatus.PR_REQUESTED})
        self.diffs[diff_id] = requested
        result = await send_signed_github_webhook(requested, webhook_url, webhook_secret)
        updated = requested.model_copy(update={"status": DiffStatus.PR_CREATED, "pr_url": result.pr_url})
        self.diffs[diff_id] = updated
        return RequestPrResponse(**updated.model_dump(), branch=result.branch, commit_sha=result.commit_sha)

    async def tool_routing_smoke(self, payload: DiffCreate) -> DiffResult:
        output = self.managed_agents.routing_smoke(
            allowed_tools=payload.allowed_tools,
            use_managed_agent=payload.use_managed_agent,
        )
        prompt_after = output.prompt_after or "Tool routing smoke check completed."
        return DiffResult(
            id=f"smoke_{uuid.uuid4().hex[:10]}",
            provider_mode=output.provider_mode,
            status=DiffStatus.READY,
            prompt_before=payload.prompt,
            prompt_after=prompt_after,
            unified_diff=unified_prompt_diff(payload.prompt, prompt_after, payload.target_path or DEFAULT_TARGET_PATH),
            interaction_id=output.interaction_id,
            environment_id=output.environment_id,
            tool_route=output.tool_route,
            target_path=payload.target_path or DEFAULT_TARGET_PATH,
        )


def unified_prompt_diff(prompt_before: str, prompt_after: str, target_path: str) -> str:
    before_lines = prompt_before.rstrip().splitlines()
    after_lines = prompt_after.rstrip().splitlines()
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{target_path}",
        tofile=f"b/{target_path}",
        lineterm="",
    )
    return "\n".join(diff) + "\n"


async def send_signed_github_webhook(
    diff: DiffResult,
    webhook_url: str,
    webhook_secret: str,
) -> GitHubWebhookResult:
    payload: dict[str, Any] = {
        "diffId": diff.id,
        "promptAfter": diff.prompt_after,
        "unifiedDiff": diff.unified_diff,
        "targetPath": diff.target_path or DEFAULT_TARGET_PATH,
        "title": "chore: apply DevBox prompt hardening diff",
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    digest = hmac.new(webhook_secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "content-type": "application/json",
        "x-devbox-signature": f"sha256={digest}",
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(webhook_url, content=body, headers=headers)
    if response.status_code >= 400:
        raise DiffManagerError(response.status_code, f"GitHub PR creation failed: {response.text}")

    data = response.json()
    pr_url = data.get("prUrl")
    if not isinstance(pr_url, str) or not pr_url:
        raise DiffManagerError(502, "GitHub webhook did not return a PR URL.")
    return GitHubWebhookResult(
        pr_url=pr_url,
        branch=data.get("branch") if isinstance(data.get("branch"), str) else None,
        commit_sha=data.get("commitSha") if isinstance(data.get("commitSha"), str) else None,
    )
