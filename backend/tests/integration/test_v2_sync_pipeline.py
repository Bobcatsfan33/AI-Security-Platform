"""End-to-end: mock connector → SyncService → ai_assets → /v1/assets.

Hits real Postgres (NullPool) and Redis. Skipped automatically when
those services aren't reachable, so the unit test path still works on
a developer machine without docker compose up.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app.db.models.ai_asset import AIAsset
from app.db.models.asset_changelog import AssetChangelog
from app.db.models.connector import Connector
from app.db.models.sync_job import SyncJob
from app.db.session import SessionLocal
from app.services.sync_service import SyncService


pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def cleanup_connector():
    """Yield a fresh mock connector and CASCADE-delete it after the test."""
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


async def test_first_run_discovers_ten_assets(cleanup_connector) -> None:
    """A first-run sync produces exactly the mock's 10 assets, an active
    sync_jobs row, a populated changelog, and updates the connector's
    last_sync_status."""
    service = SyncService()
    async with SessionLocal() as db:
        result = await service.run(db, cleanup_connector.id)

    assert result.status == "completed"
    assert result.assets_discovered == 10
    assert result.assets_updated == 0
    assert result.assets_removed == 0

    async with SessionLocal() as db:
        assets = (
            await db.execute(
                select(AIAsset).where(AIAsset.connector_id == cleanup_connector.id)
            )
        ).scalars().all()
        assert len(assets) == 10
        # All 6 types present
        assert {a.asset_type for a in assets} == {
            "model", "endpoint", "dataset", "pipeline", "agent", "tool",
        }
        # Every asset is active and tied to this connector
        assert all(a.asset_status == "active" for a in assets)

        sync_jobs = (
            await db.execute(
                select(SyncJob).where(SyncJob.connector_id == cleanup_connector.id)
            )
        ).scalars().all()
        assert len(sync_jobs) == 1
        assert sync_jobs[0].status == "completed"

        changelog_count = len(
            (
                await db.execute(
                    select(AssetChangelog).where(
                        AssetChangelog.asset_id.in_([a.id for a in assets])
                    )
                )
            ).scalars().all()
        )
        assert changelog_count == 10

        connector = (
            await db.execute(
                select(Connector).where(Connector.id == cleanup_connector.id)
            )
        ).scalar_one()
        assert connector.last_sync_status == "completed"
        assert connector.last_sync_at is not None


async def test_second_run_is_idempotent(cleanup_connector) -> None:
    """Running the sync twice with the same stable mock yields zero new
    assets, zero updates (snapshots match), and zero removals."""
    service = SyncService()
    async with SessionLocal() as db:
        first = await service.run(db, cleanup_connector.id)
    assert first.status == "completed"
    assert first.assets_discovered == 10

    async with SessionLocal() as db:
        second = await service.run(db, cleanup_connector.id)
    assert second.status == "completed"
    # Incremental sync mode — mock returns only half the assets, none of
    # which differ from the persisted rows, so updated/removed should be 0.
    assert second.assets_discovered == 0
    assert second.assets_updated == 0
    assert second.assets_removed == 0

    async with SessionLocal() as db:
        assets = (
            await db.execute(
                select(AIAsset).where(AIAsset.connector_id == cleanup_connector.id)
            )
        ).scalars().all()
        assert len(assets) == 10  # unchanged
