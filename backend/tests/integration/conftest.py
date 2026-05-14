"""Integration test fixtures — require live Postgres + Redis.

Run with:

    docker compose up -d postgres redis
    cd backend && alembic upgrade head
    pytest -m integration

The fixtures clean up rows they create so tests can run repeatedly without
manual reset. We do NOT truncate the whole DB.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text

# Test settings must be in place before any app imports load Settings.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-must-be-at-least-32-chars-long-for-pydantic-validation",
)
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://platform:platform@localhost:5432/platform"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")

# Replace the production async engine with one that uses NullPool. The
# pooled engine ties its connections to whatever event loop opened them;
# pytest-asyncio creates per-test loops, which leaves the pool with stale
# connections attached to dead loops. NullPool opens a fresh connection
# per acquire and disposes it on release — the right trade for tests.
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from app.db import session as _db_session  # noqa: E402

_test_engine = create_async_engine(
    os.environ["DATABASE_URL"],
    poolclass=NullPool,
    echo=False,
)
_db_session.engine = _test_engine
_db_session.SessionLocal = async_sessionmaker(
    bind=_test_engine, expire_on_commit=False
)

from app.db.models.connector import Connector  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402


@pytest_asyncio.fixture
async def fresh_mock_connector() -> AsyncIterator[Connector]:
    """Insert a v2 mock connector row, yield it, then delete (CASCADE)."""
    row = Connector(
        id=uuid.uuid4(),
        name=f"mock-{uuid.uuid4().hex[:6]}",
        connector_type="mock",
        config_encrypted={"stable": True},
        is_enabled=True,
    )
    async with SessionLocal() as db:
        db.add(row)
        await db.commit()
        await db.refresh(row)

    yield row

    async with SessionLocal() as db:
        await db.execute(
            text("DELETE FROM connectors WHERE id = :id"), {"id": row.id}
        )
        await db.commit()


@pytest.fixture
def app_client():
    """ASGI client for hitting the FastAPI app in-process."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")
