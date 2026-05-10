"""Integration test fixtures — require live Postgres + Redis.

Run with:

    docker compose up -d postgres redis
    cd backend && alembic upgrade head
    pytest -m integration

The fixtures clean up rows they create so tests can run repeatedly without
manual reset. We do NOT truncate the whole DB — other tests (or a dev
working alongside the suite) may have data we shouldn't touch.
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
# connections attached to dead loops ("got Future attached to a different
# loop"). NullPool opens a fresh connection per acquire and disposes it on
# release — at the cost of some perf — which is the right trade for tests.
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

from app.db.models.idp_config import IdpConfig  # noqa: E402
from app.db.models.organization import Organization  # noqa: E402
from app.db.models.user import User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402


@pytest_asyncio.fixture
async def fresh_org() -> AsyncIterator[Organization]:
    """Create an org with a unique slug for one test, then clean up.

    All resources scoped to the org are CASCADEd by the FK setup, so
    deleting the Organization clears the dependent rows.
    """
    org = Organization(
        id=uuid.uuid4(),
        name="Integration Test Org",
        slug=f"int-{uuid.uuid4().hex[:10]}",
    )
    async with SessionLocal() as db:
        db.add(org)
        await db.commit()
        await db.refresh(org)

    yield org

    async with SessionLocal() as db:
        await db.execute(
            text("DELETE FROM organizations WHERE id = :id"), {"id": org.id}
        )
        await db.commit()


@pytest_asyncio.fixture
async def scim_idp(fresh_org: Organization) -> AsyncIterator[tuple[IdpConfig, str]]:
    """Provision an active SCIM IdP config for the org and return (idp, plaintext_token).

    Yields the bcrypt-hashed token in scim_config; the plaintext is what
    callers send as the bearer token in tests.
    """
    from app.scim.auth import generate_scim_token

    plaintext, hashed = generate_scim_token()
    idp = IdpConfig(
        id=uuid.uuid4(),
        org_id=fresh_org.id,
        provider_type="scim",
        display_name="Integration Test SCIM",
        status="active",
        scim_config={
            "bearer_token_hash": hashed,
            "endpoint_url": f"/v1/scim/v2/{fresh_org.slug}",
            "sync_groups": True,
            "auto_provision": True,
        },
        directory_sync={
            "enabled": True,
            "group_to_role_mapping": {
                "Engineering": "analyst",
                "Security": "admin",
            },
            "default_role": "viewer",
        },
    )
    async with SessionLocal() as db:
        db.add(idp)
        await db.commit()
        await db.refresh(idp)
    yield idp, plaintext


@pytest.fixture
def app_client():
    """ASGI client for hitting the FastAPI app in-process."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest_asyncio.fixture
async def seeded_user(fresh_org: Organization) -> AsyncIterator[User]:
    """Create one user in the fresh org. CASCADE'd on org deletion."""
    user = User(
        id=uuid.uuid4(),
        org_id=fresh_org.id,
        email=f"seed-{uuid.uuid4().hex[:6]}@example.com",
        name="Seed User",
        role="viewer",
        idp_groups=[],
        is_active=True,
    )
    async with SessionLocal() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    yield user
