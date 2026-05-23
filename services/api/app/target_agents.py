from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .contracts import AgentSpec, TargetAgentInvocation, TargetAgentInvocationResult, TargetAgentRuntime, TargetAgentTemplate


CONFIG_DIR = Path(__file__).resolve().parent / "config"
DEFAULT_TARGET_AGENT_BASE_URL = "http://localhost:8010"


class TargetAgentRegistry:
    def __init__(self, templates: list[TargetAgentTemplate]) -> None:
        self._templates = templates

    @classmethod
    def from_config(cls, path: Path = CONFIG_DIR / "target_agents.json") -> "TargetAgentRegistry":
        raw_templates = json.loads(path.read_text(encoding="utf-8"))
        return cls([TargetAgentTemplate.model_validate(raw_template) for raw_template in raw_templates])

    def list_templates(self) -> list[TargetAgentTemplate]:
        return self._templates

    def get_template(self, template_id: str) -> TargetAgentTemplate | None:
        return next((template for template in self._templates if template.id == template_id), None)

    def agent_from_template(self, template_id: str) -> AgentSpec | None:
        template = self.get_template(template_id)
        if template is None:
            return None
        return template.agent_spec.model_copy(update={"runtime": template.runtime})


class TargetAgentClient:
    def __init__(self, base_url: str = DEFAULT_TARGET_AGENT_BASE_URL) -> None:
        self.base_url = base_url.rstrip("/")

    @classmethod
    def from_env(cls) -> "TargetAgentClient":
        return cls(os.getenv("DEVBOX_TARGET_AGENT_BASE_URL", DEFAULT_TARGET_AGENT_BASE_URL))

    async def invoke(
        self,
        runtime: TargetAgentRuntime,
        invocation: TargetAgentInvocation,
    ) -> TargetAgentInvocationResult:
        url = self._resolve_url(runtime.endpoint)
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=invocation.model_dump(mode="json", by_alias=True))
        response.raise_for_status()
        return TargetAgentInvocationResult.model_validate(response.json())

    def _resolve_url(self, endpoint: str) -> str:
        parsed = urlparse(endpoint)
        if parsed.scheme and parsed.netloc:
            return endpoint
        return f"{self.base_url}/{endpoint.lstrip('/')}"
