from __future__ import annotations

import json
from pathlib import PurePosixPath

from fastapi import UploadFile
from pydantic import Field, ValidationError

from .contracts import AgentProjectImportResponse, AgentSpec, ApiModel, SandboxPolicy


MAX_MANIFEST_BYTES = 64 * 1024
MAX_PROMPT_BYTES = 256 * 1024
DEFAULT_IMPORT_SCENARIOS = [
    "web-prompt-injection",
    "rag-policy-poison",
    "honeytoken-exfiltration",
    "tool-boundary-breakout",
    "egress-allowlist-bypass",
    "authority-confusion",
]


class AgentProjectImportError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class AgentProjectManifest(ApiModel):
    name: str = Field(min_length=1, max_length=120)
    system_prompt: str | None = None
    system_prompt_path: str | None = None
    tools: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    filesystem_scope: str = "/workspace/imported-agent"
    honeytokens: list[str] = Field(default_factory=lambda: ["DEVBOX_FAKE_SECRET", "sk-devbox-honeytoken"])


async def import_agent_project(
    *,
    manifest_upload: UploadFile,
    prompt_upload: UploadFile | None,
) -> AgentProjectImportResponse:
    validate_manifest_upload(manifest_upload)
    manifest_text = await read_upload_text(manifest_upload, MAX_MANIFEST_BYTES, "Manifest")
    manifest = parse_manifest(manifest_text)

    prompt_text = normalized_prompt(manifest.system_prompt)
    warnings: list[str] = []
    if prompt_upload is not None:
        validate_prompt_upload(prompt_upload)
        uploaded_prompt = normalized_prompt(await read_upload_text(prompt_upload, MAX_PROMPT_BYTES, "Prompt file"))
        if prompt_text:
            warnings.append("Prompt file was used instead of manifest systemPrompt.")
        prompt_text = uploaded_prompt

    if not prompt_text:
        raise AgentProjectImportError(422, "Manifest must include systemPrompt or upload a promptFile.")

    return build_agent_project_response(manifest=manifest, prompt_text=prompt_text, warnings=warnings)


def build_agent_project_response(
    *,
    manifest: AgentProjectManifest,
    prompt_text: str,
    warnings: list[str] | None = None,
    prompt_path_override: str | None = None,
) -> AgentProjectImportResponse:
    response_warnings = list(warnings or [])
    tools = normalize_string_list(manifest.tools)
    allowed_domains = normalize_string_list(manifest.allowed_domains)
    honeytokens = normalize_string_list(manifest.honeytokens) or ["DEVBOX_FAKE_SECRET", "sk-devbox-honeytoken"]
    prompt_path = prompt_path_override or normalize_prompt_path(manifest.system_prompt_path)
    if manifest.system_prompt_path and prompt_path is None:
        response_warnings.append("systemPromptPath was ignored because it is not a relative file path.")
    if not tools:
        response_warnings.append("No tools were declared; tool-boundary scenarios will run against an empty allowlist.")
    if not allowed_domains:
        response_warnings.append("No allowedDomains were declared; network scenarios will treat outbound domains as blocked.")

    try:
        agent = AgentSpec(
            name=manifest.name.strip(),
            system_prompt=prompt_text,
            prompt_path=prompt_path,
            tools=tools,
            sandbox_policy=SandboxPolicy(
                allowed_tools=tools,
                allowed_domains=allowed_domains,
                filesystem_scope=manifest.filesystem_scope.strip() or "/workspace/imported-agent",
                network_egress="allowlist",
                honeytokens=honeytokens,
            ),
            managed=True,
            runtime=None,
        )
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        message = first.get("msg") if isinstance(first.get("msg"), str) else "Imported agent validation failed."
        raise AgentProjectImportError(422, message) from exc
    return AgentProjectImportResponse(
        agent=agent,
        warnings=response_warnings,
        recommended_scenario_ids=list(DEFAULT_IMPORT_SCENARIOS),
    )


def validate_manifest_upload(upload: UploadFile) -> None:
    filename = upload.filename or ""
    if filename and not filename.lower().endswith(".json"):
        raise AgentProjectImportError(415, "Manifest must be a JSON file.")


def validate_prompt_upload(upload: UploadFile) -> None:
    filename = upload.filename or ""
    if filename and not filename.lower().endswith((".md", ".txt")):
        raise AgentProjectImportError(415, "promptFile must be a .md or .txt file.")


async def read_upload_text(upload: UploadFile, limit: int, label: str) -> str:
    raw = await upload.read(limit + 1)
    if len(raw) > limit:
        raise AgentProjectImportError(413, f"{label} exceeds the {limit // 1024} KB size limit.")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentProjectImportError(422, f"{label} must be UTF-8 text.") from exc


def parse_manifest(manifest_text: str) -> AgentProjectManifest:
    try:
        payload = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        raise AgentProjectImportError(422, "Manifest must contain valid JSON.") from exc
    if not isinstance(payload, dict):
        raise AgentProjectImportError(422, "Manifest JSON must be an object.")
    try:
        return AgentProjectManifest.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        message = first.get("msg") if isinstance(first.get("msg"), str) else "Manifest validation failed."
        raise AgentProjectImportError(422, message) from exc


def normalized_prompt(value: str | None) -> str | None:
    if value is None:
        return None
    prompt = value.strip()
    return prompt or None


def normalize_string_list(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = value.strip()
        if item and item not in normalized:
            normalized.append(item)
    return normalized


def normalize_prompt_path(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip().replace("\\", "/")
    if not raw or raw.startswith("/") or "://" in raw:
        return None
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()
