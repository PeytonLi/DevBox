from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .contracts import ModelConfig, Scenario


CONFIG_DIR = Path(__file__).parent / "config"


class ProviderRegistry:
    def __init__(self, models: list[ModelConfig]) -> None:
        self._models = models

    @classmethod
    def from_config(cls, path: Path = CONFIG_DIR / "models.json") -> "ProviderRegistry":
        raw_models: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        models: list[ModelConfig] = []
        for raw_model in raw_models:
            required_env = raw_model.get("required_env")
            enabled = bool(os.getenv(required_env, "").strip()) if required_env else True
            unavailable_reason = None if enabled else f"Set {required_env} to enable provider validation."
            models.append(
                ModelConfig.model_validate(
                    {
                        **raw_model,
                        "enabled": enabled,
                        "unavailable_reason": unavailable_reason,
                    }
                )
            )
        return cls(models)

    def list_models(self) -> list[ModelConfig]:
        return self._models

    def get_model(self, model_id: str) -> ModelConfig | None:
        return next((model for model in self._models if model.model_id == model_id), None)


class ScenarioRegistry:
    def __init__(self, scenarios: list[Scenario]) -> None:
        self._scenarios = scenarios

    @classmethod
    def from_config(cls, path: Path = CONFIG_DIR / "scenarios.json") -> "ScenarioRegistry":
        raw_scenarios = json.loads(path.read_text(encoding="utf-8"))
        return cls([Scenario.model_validate(raw_scenario) for raw_scenario in raw_scenarios])

    def list_scenarios(self) -> list[Scenario]:
        return self._scenarios

    def get_scenario(self, scenario_id: str) -> Scenario | None:
        return next((scenario for scenario in self._scenarios if scenario.id == scenario_id), None)
