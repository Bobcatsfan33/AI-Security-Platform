"""The tests that make tenant isolation a guarantee, not a convention.

Marked integration: requires Postgres (RLS does not exist on SQLite, and the
Wall-1 guard is exercised against real org rows). CI runs Postgres for the
integration suite.

Wall 1 (ORM guard) is proven against the owner connection with the guard
installed. Wall 2 (RLS) is proven against a freshly-created NOBYPASSRLS role —
the owner/superuser bypasses RLS even under FORCE, so the raw-SQL test connects
as a non-privileged role, exactly as production does (asp_app).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import pytest
import pytest_asyncio
from sqlalchemy import event, select, text, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.db.models.connector import Connector
from app.db.models.organization import Organization
from app.db.session import SessionLocal
from app.db.tenancy import _tenant_guard, current_org_id, install_tenant_guard

pytestmark = pytest.mark.integration

_APP_ROLE = "asp_app_test"
_APP_PW = "asp_app_test_pw"


@pytest_asyncio.fixture
async def guard_installed() -> AsyncIterator[None]:
    """Arm Wall 1 for the test, then remove it so other tests are unaffected."""
    install_tenant_guard()
    # The guard reads current_org_id; default it to None (fail-closed) and let
    # each test set it explicitly.
    token = current_org_id.set(None)
    try:
        yield
    finally:
        current_org_id.reset(token)
        if event.contains(Session, "do_orm_execute", _tenant_guard):
            event.remove(Session, "do_orm_execute", _tenant_guard)


async def _make_org(slug_suffix: str) -> uuid.UUID:
    org_id = uuid.uuid4()
    async with SessionLocal() as db:
        db.add(
            Organization(
                id=org_id, name=f"guard-{slug_suffix}", slug=f"guard-{uuid.uuid4().hex[:8]}"
            )
        )
        await db.commit()
    return org_id


async def _delete_org(org_id: uuid.UUID) -> None:
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


@pytest_asyncio.fixture
async def org_a() -> AsyncIterator[uuid.UUID]:
    oid = await _make_org("a")
    yield oid
    await _delete_org(oid)


@pytest_asyncio.fixture
async def org_b() -> AsyncIterator[uuid.UUID]:
    oid = await _make_org("b")
    yield oid
    await _delete_org(oid)


async def _make_connector(org_id: uuid.UUID, name: str) -> uuid.UUID:
    cid = uuid.uuid4()
    async with SessionLocal() as db:
        db.add(
            Connector(
                id=cid,
                org_id=org_id,
                name=name,
                connector_type="mock",
                config_encrypted={"x": True},
                is_enabled=True,
            )
        )
        await db.commit()
    return cid


@pytest.mark.asyncio
async def test_orm_guard_filters_cross_tenant_reads(guard_installed, org_a, org_b):
    cid_b = await _make_connector(org_b, "victim-b")
    current_org_id.set(org_a)
    async with SessionLocal() as db:
        rows = (await db.execute(select(Connector))).scalars().all()
    assert cid_b not in {r.id for r in rows}


@pytest.mark.asyncio
async def test_no_context_fails_closed(guard_installed, org_b):
    await _make_connector(org_b, "should-be-invisible")
    current_org_id.set(None)
    async with SessionLocal() as db:
        rows = (await db.execute(select(Connector))).scalars().all()
    assert rows == []  # zero rows, never all rows


@pytest.mark.asyncio
async def test_orm_guard_blocks_cross_tenant_update(guard_installed, org_a, org_b):
    cid_b = await _make_connector(org_b, "original")
    # Acting as org A, try to rename every connector.
    current_org_id.set(org_a)
    async with SessionLocal() as db:
        await db.execute(update(Connector).values(name="pwned"))
        await db.commit()
    # Org B's row is untouched.
    current_org_id.set(org_b)
    async with SessionLocal() as db:
        row = (await db.execute(select(Connector).where(Connector.id == cid_b))).scalar_one()
        assert row.name == "original"


@pytest.mark.asyncio
async def test_rls_blocks_raw_sql_as_unprivileged_role(org_a, org_b):
    """Wall 2: a NOBYPASSRLS role with the GUC set to org A cannot read org B's
    row even via raw SQL with the ORM guard entirely out of the picture."""
    cid_b = await _make_connector(org_b, "rls-victim")

    # Create the unprivileged role + grants using the owner (superuser) engine.
    async with SessionLocal() as db:
        await db.execute(
            text(
                "DO $$ BEGIN "
                f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{_APP_ROLE}') THEN "
                f"CREATE ROLE {_APP_ROLE} LOGIN PASSWORD '{_APP_PW}' NOBYPASSRLS; "
                "END IF; END $$;"
            )
        )
        await db.execute(text(f"GRANT USAGE ON SCHEMA public TO {_APP_ROLE}"))
        await db.execute(text(f"GRANT SELECT ON connectors TO {_APP_ROLE}"))
        await db.commit()

    # Build a DSN for the unprivileged role by swapping the credentials.
    import os

    parts = urlsplit(os.environ["DATABASE_URL"])
    netloc = f"{_APP_ROLE}:{_APP_PW}@{parts.hostname}:{parts.port or 5432}"
    app_dsn = urlunsplit((parts.scheme, netloc, parts.path, "", ""))

    app_engine = create_async_engine(app_dsn, poolclass=NullPool)
    try:
        async with app_engine.connect() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_org', :o, true)"),
                {"o": str(org_a)},
            )
            rows = (
                await conn.execute(
                    text("SELECT id FROM connectors WHERE id = :b"), {"b": str(cid_b)}
                )
            ).fetchall()
        assert rows == []  # RLS hid org B's row from the org-A-scoped connection
    finally:
        await app_engine.dispose()
