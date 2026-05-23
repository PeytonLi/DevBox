from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import httpx
import jwt

from .agent_projects import AgentProjectManifest, build_agent_project_response, parse_manifest
from .contracts import AgentProjectImportResponse, GitHubImportSource


class GitHubIntegrationError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class GitHubFileContent:
    path: str
    text: str
    sha: str | None = None


@dataclass(frozen=True)
class GitHubRepositoryMetadata:
    owner: str
    repo: str
    full_name: str
    default_branch: str | None
    html_url: str | None


@dataclass(frozen=True)
class FetchedGitHubAgent:
    source: GitHubImportSource
    repository: GitHubRepositoryMetadata
    import_response: AgentProjectImportResponse
    commit_sha: str | None


class GitHubAppClient:
    def __init__(
        self,
        *,
        app_id: str | None,
        private_key: str | None,
        installation_id: int | None,
        token: str | None,
        api_base_url: str = "https://api.github.com",
    ) -> None:
        self.app_id = app_id
        self.private_key = normalize_private_key(private_key or "") if private_key else None
        self.installation_id = installation_id
        self.token = token
        self.api_base_url = api_base_url.rstrip("/")

    @classmethod
    def from_env(cls) -> "GitHubAppClient":
        installation = os.getenv("GITHUB_APP_INSTALLATION_ID", "").strip()
        return cls(
            app_id=os.getenv("GITHUB_APP_ID", "").strip() or None,
            private_key=os.getenv("GITHUB_APP_PRIVATE_KEY", "").strip() or None,
            installation_id=int(installation) if installation.isdigit() else None,
            token=os.getenv("GITHUB_TOKEN", "").strip() or None,
            api_base_url=os.getenv("GITHUB_API_BASE_URL", "https://api.github.com"),
        )

    async def fetch_agent(self, source: GitHubImportSource) -> FetchedGitHubAgent:
        source = normalize_source(source)
        token = await self._installation_token(source)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            repository = await self._repo_metadata(client, source)
            prompt_file = await self._file_content(client, source, source.prompt_path)
            manifest_file = None
            warnings: list[str] = []
            if source.manifest_path:
                try:
                    manifest_file = await self._file_content(client, source, source.manifest_path)
                except GitHubIntegrationError as exc:
                    if exc.status_code != 404:
                        raise
                    warnings.append(f"{source.manifest_path} was not found; imported with an empty tool/domain policy.")

        manifest = manifest_from_files(source, repository, prompt_file, manifest_file, warnings)
        import_response = build_agent_project_response(
            manifest=manifest,
            prompt_text=prompt_file.text,
            warnings=warnings,
            prompt_path_override=source.prompt_path,
        )
        return FetchedGitHubAgent(
            source=source,
            repository=repository,
            import_response=import_response,
            commit_sha=prompt_file.sha,
        )

    async def _installation_token(self, source: GitHubImportSource) -> str:
        if self.token:
            return self.token
        installation_id = source.installation_id or self.installation_id
        if not self.app_id or not self.private_key:
            raise GitHubIntegrationError(503, "GitHub App credentials are not configured.")
        app_jwt = self._app_jwt()
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            if installation_id is None:
                response = await client.get(f"{self.api_base_url}/repos/{source.owner}/{source.repo}/installation")
                if response.status_code >= 400:
                    raise github_error(response, "GitHub App installation lookup failed")
                installation_id = int(response.json()["id"])
            response = await client.post(f"{self.api_base_url}/app/installations/{installation_id}/access_tokens")
        if response.status_code >= 400:
            raise github_error(response, "GitHub App token creation failed")
        token = response.json().get("token")
        if not isinstance(token, str) or not token:
            raise GitHubIntegrationError(502, "GitHub App token response did not include a token.")
        return token

    def _app_jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 600, "iss": self.app_id}
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    async def _repo_metadata(self, client: httpx.AsyncClient, source: GitHubImportSource) -> GitHubRepositoryMetadata:
        response = await client.get(f"{self.api_base_url}/repos/{source.owner}/{source.repo}")
        if response.status_code >= 400:
            raise github_error(response, "GitHub repository lookup failed")
        payload = response.json()
        return GitHubRepositoryMetadata(
            owner=source.owner,
            repo=source.repo,
            full_name=str(payload.get("full_name") or f"{source.owner}/{source.repo}"),
            default_branch=payload.get("default_branch") if isinstance(payload.get("default_branch"), str) else None,
            html_url=payload.get("html_url") if isinstance(payload.get("html_url"), str) else None,
        )

    async def _file_content(self, client: httpx.AsyncClient, source: GitHubImportSource, path: str) -> GitHubFileContent:
        params = {"ref": source.ref} if source.ref else None
        response = await client.get(f"{self.api_base_url}/repos/{source.owner}/{source.repo}/contents/{path}", params=params)
        if response.status_code >= 400:
            raise github_error(response, f"GitHub file lookup failed for {path}")
        payload = response.json()
        if isinstance(payload, list) or payload.get("type") != "file":
            raise GitHubIntegrationError(422, f"{path} must be a file, not a directory.")
        content = payload.get("content")
        if not isinstance(content, str):
            raise GitHubIntegrationError(502, f"GitHub file response for {path} did not include content.")
        try:
            raw = base64.b64decode(content.replace("\n", ""), validate=False)
            text = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GitHubIntegrationError(422, f"{path} must be UTF-8 text.") from exc
        return GitHubFileContent(path=path, text=text, sha=payload.get("sha") if isinstance(payload.get("sha"), str) else None)


def manifest_from_files(
    source: GitHubImportSource,
    repository: GitHubRepositoryMetadata,
    prompt_file: GitHubFileContent,
    manifest_file: GitHubFileContent | None,
    warnings: list[str],
) -> AgentProjectManifest:
    if manifest_file:
        manifest = parse_manifest(manifest_file.text)
        if manifest.system_prompt:
            warnings.append(f"{prompt_file.path} was used instead of manifest systemPrompt.")
        return manifest.model_copy(update={"system_prompt_path": prompt_file.path})
    return AgentProjectManifest(
        name=f"{repository.full_name} agent",
        system_prompt=prompt_file.text,
        system_prompt_path=prompt_file.path,
        tools=[],
        allowed_domains=[],
        filesystem_scope=f"/workspace/github/{source.owner}/{source.repo}",
    )


def normalize_source(source: GitHubImportSource) -> GitHubImportSource:
    prompt_path = normalize_github_path(source.prompt_path, "promptPath")
    manifest_path = normalize_github_path(source.manifest_path, "manifestPath") if source.manifest_path else None
    return source.model_copy(update={"prompt_path": prompt_path, "manifest_path": manifest_path})


def normalize_github_path(value: str, label: str) -> str:
    raw = value.strip().replace("\\", "/")
    if not raw or raw.startswith("/") or "://" in raw:
        raise GitHubIntegrationError(422, f"{label} must be a relative repository file path.")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise GitHubIntegrationError(422, f"{label} must not include . or .. segments.")
    return path.as_posix()


def normalize_private_key(value: str) -> str:
    normalized = value.strip().strip("'\"").replace("\\n", "\n").replace("\r\n", "\n")
    if "-----BEGIN" in normalized:
        return normalized
    compact = "".join(normalized.split())
    if compact:
        lines = [compact[index : index + 64] for index in range(0, len(compact), 64)]
        return "\n".join(["-----BEGIN PRIVATE KEY-----", *lines, "-----END PRIVATE KEY-----"])
    return normalized


def github_error(response: httpx.Response, prefix: str) -> GitHubIntegrationError:
    detail = response.text
    try:
        payload: Any = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        detail = payload["message"]
    return GitHubIntegrationError(response.status_code, f"{prefix}: {detail}")
