from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_local_env() -> None:
    root_env = Path(__file__).resolve().parents[3] / ".env"
    if root_env.exists():
        load_dotenv(root_env, override=False)
