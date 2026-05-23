from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Coroutine
from typing import Any

from celery import Celery

from .database import init_database
from .persistence import PersistentStore
from .registries import ProviderRegistry, ScenarioRegistry
from .run_manager import RunManager
from .target_agents import TargetAgentClient


def redis_url() -> str | None:
    return os.getenv("REDIS_URL", "").strip() or None


def eager_tasks_enabled() -> bool:
    raw = os.getenv("DEVBOX_CELERY_EAGER", "").strip().lower()
    if raw in {"1", "true", "yes"}:
        return True
    if raw in {"0", "false", "no"}:
        return False
    return redis_url() is None


broker_url = redis_url() or "memory://"
celery_app = Celery("devbox", broker=broker_url, backend=redis_url() or "cache+memory://")
celery_app.conf.update(
    task_always_eager=eager_tasks_enabled(),
    task_eager_propagates=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    broker_connection_retry_on_startup=True,
)


@celery_app.task(name="devbox.execute_run")
def execute_run_task(run_id: str) -> str:
    init_database(reset=False)
    manager = RunManager(
        ProviderRegistry.from_config(),
        ScenarioRegistry.from_config(),
        TargetAgentClient.from_env(),
        PersistentStore(),
    )
    run_coroutine_sync(manager.execute_run(run_id))
    return run_id


def enqueue_run(run_id: str) -> None:
    execute_run_task.delay(run_id)


def run_coroutine_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}

    def target() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001 - propagate across the worker thread boundary.
            result["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")
