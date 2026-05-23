from __future__ import annotations

import os
from datetime import timedelta

import jwt
from fastapi import HTTPException, Request

from .contracts import EventsTokenResponse, utc_now


def api_service_token() -> str:
    return os.getenv("DEVBOX_API_SERVICE_TOKEN", "").strip()


def production_mode() -> bool:
    return os.getenv("DEVBOX_ENV", "").strip().lower() == "production"


def verify_service_request(request: Request) -> None:
    expected = api_service_token()
    if not expected:
        if production_mode():
            raise HTTPException(status_code=503, detail="DEVBOX_API_SERVICE_TOKEN is required in production.")
        return

    header = request.headers.get("authorization", "")
    if header != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Invalid API service token.")


def events_token_secret() -> str:
    return (
        os.getenv("DEVBOX_EVENTS_TOKEN_SECRET", "").strip()
        or api_service_token()
        or os.getenv("DEVBOX_PR_WEBHOOK_SECRET", "").strip()
        or "devbox-local-events-secret"
    )


def create_events_token(run_id: str, *, ttl_seconds: int = 300) -> EventsTokenResponse:
    expires_at = utc_now() + timedelta(seconds=ttl_seconds)
    payload = {"sub": run_id, "exp": expires_at}
    token = jwt.encode(payload, events_token_secret(), algorithm="HS256")
    return EventsTokenResponse(run_id=run_id, token=token, expires_at=expires_at)


def verify_events_token(run_id: str, token: str | None) -> None:
    if not token:
        if production_mode():
            raise HTTPException(status_code=401, detail="Run event stream token is required.")
        return
    try:
        payload = jwt.decode(token, events_token_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid run event stream token.") from exc
    if payload.get("sub") != run_id:
        raise HTTPException(status_code=401, detail="Run event stream token does not match run.")
