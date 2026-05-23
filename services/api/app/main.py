from __future__ import annotations

from contextlib import asynccontextmanager
import os
from typing import Annotated

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .agent_projects import AgentProjectImportError, import_agent_project
from .env import load_local_env
from .contracts import (
    AgentSpec,
    AgentProjectImportResponse,
    ApproveFixRequest,
    ApproveFixResponse,
    DiffCreate,
    DiffResult,
    HealthResponse,
    ModelConfig,
    RequestPrResponse,
    Report,
    Run,
    RunCreate,
    Scenario,
    TargetAgentTemplate,
)
from .diff_manager import DiffManager, DiffManagerError
from .managed_agents import ManagedAgentClient
from .registries import ProviderRegistry, ScenarioRegistry
from .run_manager import RunManager, RunManagerError
from .target_agents import TargetAgentClient, TargetAgentRegistry


VERSION = "0.1.0"


load_local_env()


@asynccontextmanager
async def lifespan(app: FastAPI):
    providers = ProviderRegistry.from_config()
    scenarios = ScenarioRegistry.from_config()
    target_agents = TargetAgentRegistry.from_config()
    target_agent_client = TargetAgentClient.from_env()
    app.state.target_agent_registry = target_agents
    app.state.run_manager = RunManager(providers, scenarios, target_agent_client)
    app.state.managed_agents = ManagedAgentClient.from_env()
    app.state.diff_manager = DiffManager(app.state.managed_agents)
    yield
    app.state.managed_agents.close()


app = FastAPI(
    title="DevBox Agent Security Lab API",
    version=VERSION,
    description="Authorized sandboxed assessment API for managed or opt-in AI agents.",
    lifespan=lifespan,
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "DEVBOX_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def manager_from(request: Request) -> RunManager:
    return request.app.state.run_manager


def raise_for_manager_error(exc: RunManagerError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def diff_manager_from(request: Request) -> DiffManager:
    return request.app.state.diff_manager


def raise_for_diff_error(exc: DiffManagerError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def target_agent_registry_from(request: Request) -> TargetAgentRegistry:
    return request.app.state.target_agent_registry


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="devbox-api", version=VERSION)


@app.get("/v1/models", response_model=list[ModelConfig])
async def list_models(request: Request) -> list[ModelConfig]:
    return manager_from(request).providers.list_models()


@app.get("/v1/scenarios", response_model=list[Scenario])
async def list_scenarios(request: Request) -> list[Scenario]:
    return manager_from(request).scenarios.list_scenarios()


@app.get("/v1/target-agents", response_model=list[TargetAgentTemplate])
async def list_target_agents(request: Request) -> list[TargetAgentTemplate]:
    return target_agent_registry_from(request).list_templates()


@app.post("/v1/target-agents/{target_agent_id}/register", response_model=AgentSpec, status_code=201)
async def register_target_agent(target_agent_id: str, request: Request) -> AgentSpec:
    agent = target_agent_registry_from(request).agent_from_template(target_agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Target agent template not found.")
    return await manager_from(request).create_agent(agent)


@app.post("/v1/agents", response_model=AgentSpec, status_code=201)
async def create_agent(agent: AgentSpec, request: Request) -> AgentSpec:
    return await manager_from(request).create_agent(agent)


@app.post("/v1/agent-projects/import", response_model=AgentProjectImportResponse, status_code=201)
async def import_agent_project_endpoint(
    request: Request,
    manifest: Annotated[UploadFile, File()],
    prompt_file: Annotated[UploadFile | None, File(alias="promptFile")] = None,
) -> AgentProjectImportResponse:
    try:
        imported = await import_agent_project(manifest_upload=manifest, prompt_upload=prompt_file)
    except AgentProjectImportError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    agent = await manager_from(request).create_agent(imported.agent)
    return imported.model_copy(update={"agent": agent})


@app.post("/v1/runs", response_model=Run, status_code=201)
async def create_run(payload: RunCreate, request: Request, background_tasks: BackgroundTasks) -> Run:
    manager = manager_from(request)
    try:
        run = await manager.create_run(payload)
    except RunManagerError as exc:
        raise_for_manager_error(exc)
    background_tasks.add_task(manager.execute_run, run.id)
    return run


@app.get("/v1/runs/{run_id}", response_model=Run)
async def get_run(run_id: str, request: Request) -> Run:
    run = manager_from(request).get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@app.get("/v1/runs/{run_id}/report", response_model=Report)
async def get_report(run_id: str, request: Request) -> Report:
    manager = manager_from(request)
    if manager.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    report = manager.get_report(run_id)
    if report is None:
        raise HTTPException(status_code=409, detail="Report is not ready.")
    return report


@app.post("/v1/runs/{run_id}/approve-fix", response_model=ApproveFixResponse)
async def approve_fix(run_id: str, payload: ApproveFixRequest, request: Request) -> ApproveFixResponse:
    try:
        return await manager_from(request).approve_fix(run_id, payload)
    except RunManagerError as exc:
        raise_for_manager_error(exc)


@app.post("/v1/runs/{run_id}/request-pr", response_model=RequestPrResponse)
async def request_run_pr(run_id: str, request: Request) -> RequestPrResponse:
    try:
        return await manager_from(request).request_pr(run_id)
    except RunManagerError as exc:
        raise_for_manager_error(exc)


@app.post("/v1/diffs", response_model=DiffResult, status_code=201)
async def create_diff(payload: DiffCreate, request: Request) -> DiffResult:
    try:
        return await diff_manager_from(request).create_diff(payload)
    except DiffManagerError as exc:
        raise_for_diff_error(exc)


@app.post("/v1/diffs/{diff_id}/request-pr", response_model=RequestPrResponse)
async def request_diff_pr(diff_id: str, request: Request) -> RequestPrResponse:
    try:
        return await diff_manager_from(request).request_pr(diff_id)
    except DiffManagerError as exc:
        raise_for_diff_error(exc)


@app.post("/v1/managed-agent/tool-routing-smoke", response_model=DiffResult)
async def managed_agent_tool_routing_smoke(payload: DiffCreate, request: Request) -> DiffResult:
    try:
        return await diff_manager_from(request).tool_routing_smoke(payload)
    except DiffManagerError as exc:
        raise_for_diff_error(exc)


@app.websocket("/v1/runs/{run_id}/events")
async def run_events(run_id: str, websocket: WebSocket) -> None:
    await websocket.accept()
    manager: RunManager = websocket.app.state.run_manager
    try:
        async for event in manager.subscribe(run_id):
            payload = event.model_dump(mode="json", by_alias=True)
            await websocket.send_json(payload)
    except RunManagerError:
        await websocket.close(code=1008)
    except WebSocketDisconnect:
        return
    else:
        await websocket.close(code=1000)
