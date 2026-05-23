from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip() or os.getenv("DEVBOX_DATABASE_URL", "").strip()
    if not url:
        return "sqlite:///./devbox.local.db"
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://") and "+psycopg" not in url:
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def create_database_engine() -> Engine:
    url = database_url()
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if url.endswith(":memory:"):
            return create_engine(url, connect_args=connect_args, poolclass=StaticPool)
        return create_engine(url, connect_args=connect_args)
    return create_engine(url, pool_pre_ping=True)


engine = create_database_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def init_database(*, reset: bool = False) -> None:
    from . import db_models  # noqa: F401

    attempts = int(os.getenv("DEVBOX_DATABASE_INIT_ATTEMPTS", "5"))
    for attempt in range(1, attempts + 1):
        try:
            if reset:
                Base.metadata.drop_all(bind=engine)
            Base.metadata.create_all(bind=engine)
            return
        except SQLAlchemyError:
            if attempt == attempts:
                raise
            time.sleep(min(attempt, 5))


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
