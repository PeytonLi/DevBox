from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone


def main() -> None:
    parser = argparse.ArgumentParser(description="DevBox sandbox smoke entrypoint.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    payload = {
        "status": "ok",
        "sandbox": "devbox-ephemeral",
        "network": "disabled-by-default",
        "filesystem_scope": "/workspace",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if args.self_test:
        payload["check"] = "self-test"
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
