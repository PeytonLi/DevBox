from __future__ import annotations

import sys
import os
from pathlib import Path


SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))

os.environ.setdefault("DEVBOX_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("DEVBOX_RESET_DATABASE_ON_STARTUP", "true")
os.environ.setdefault("DEVBOX_CELERY_EAGER", "true")
