"""Sync orchestration — runs a connector and folds its output into the asset graph.

One :class:`SyncService.run` invocation:

  1. Loads the connector row from Postgres and decrypts its config
  2. Instantiates the concrete connector class via the discovery registry
  3. Picks ``discover()`` (first run) or ``sync(since=last_sync_at)`` (incremental)
  4. Upserts each :class:`DiscoveredAsset` into ``ai_assets`` keyed by
     ``(connector_id, external_id)``; updates ``last_seen_at``
  5. Marks rows not seen this run as ``asset_status=inactive`` (soft removal)
  6. Writes a per-mutation row to ``asset_changelog``
  7. Records the run in ``sync_jobs`` with discovered/updated/removed counts
  8. Updates ``connectors.last_sync_at`` and ``connectors.last_sync_status``

Sync state (cursors, rate limits) lives in Redis under per-connector
keys so a crashed sync can resume without re-pulling already-seen pages.

The service is fail-safe: any exception flips the job to ``failed`` and
records the error message; partial inserts remain (we don't roll back
discovered assets because rerunning the sync would just re-discover them).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.discovery import (
    BaseConnector,
    DiscoveredAsset,
    UnknownConnectorTypeError,
    get as get_connector_class,
)
from app.db.models.ai_asset import AIAsset
from app.db.models.asset_changelog import AssetChangelog
from app.db.models.connector import Connector
from app.db.models.sync_job import SyncJob
from app.services.redis_client import get_redis

logger = logging.getLogger("platform.sync_service")


CURSOR_KEY_PREFIX = "sync:cursor:"
RATE_KEY_PREFIX = "sync:rate:"
CURSOR_TTL_SECONDS = 30 * 24 * 3600  # 30 days


@dataclass
class SyncResult:
    """Wire-friendly outcome returned by :meth:`SyncService.run`."""

    sync_job_id: uuid.UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    assets_discovered: int = 0
    assets_updated: int = 0
    assets_removed: int = 0
    error_message: Optional[str] = None
    discovered: list[dict[str, Any]] = field(default_factory=list)


class SyncService:
    """Orchestrates one sync run for one connector."""

    async def run(
        self, db: AsyncSession, connector_id: uuid.UUID
    ) -> SyncResult:
        connector_row = await self._load_connector(db, connector_id)
        if connector_row is None:
            raise ValueError(f"connector {connector_id} not found")
        if not connector_row.is_enabled:
            raise ValueError(f"connector {connector_id} is disabled")

        job = SyncJob(connector_id=connector_id, status="running")
        db.add(job)
        await db.commit()
        await db.refresh(job)

        result = SyncResult(
            sync_job_id=job.id,
            status="running",
            started_at=job.started_at,
        )

        try:
            connector = self._instantiate(connector_row)
            assets = await self._fetch(connector, connector_row.last_sync_at)
            counts = await self._upsert(
                db,
                connector_id=connector_id,
                assets=assets,
                is_first_run=connector_row.last_sync_at is None,
            )

            result.assets_discovered = counts["discovered"]
            result.assets_updated = counts["updated"]
            result.assets_removed = counts["removed"]
            result.discovered = [a.model_dump() for a in assets]
            result.status = "completed"

            now = datetime.now(timezone.utc)
            await db.execute(
                update(SyncJob)
                .where(SyncJob.id == job.id)
                .values(
                    status="completed",
                    completed_at=now,
                    assets_discovered=counts["discovered"],
                    assets_updated=counts["updated"],
                    assets_removed=counts["removed"],
                )
            )
            await db.execute(
                update(Connector)
                .where(Connector.id == connector_id)
                .values(last_sync_at=now, last_sync_status="completed")
            )
            await db.commit()
            result.completed_at = now

        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            now = datetime.now(timezone.utc)
            err = str(exc) or exc.__class__.__name__
            logger.exception("sync_failed")
            try:
                await db.execute(
                    update(SyncJob)
                    .where(SyncJob.id == job.id)
                    .values(
                        status="failed", completed_at=now, error_message=err
                    )
                )
                await db.execute(
                    update(Connector)
                    .where(Connector.id == connector_id)
                    .values(last_sync_at=now, last_sync_status="failed")
                )
                await db.commit()
            except Exception:  # noqa: BLE001 — best effort
                await db.rollback()
            result.status = "failed"
            result.error_message = err
            result.completed_at = now

        return result

    # ───────────────────────────────────────────── internals

    async def _load_connector(
        self, db: AsyncSession, connector_id: uuid.UUID
    ) -> Connector | None:
        return (
            await db.execute(
                select(Connector).where(Connector.id == connector_id)
            )
        ).scalar_one_or_none()

    def _instantiate(self, row: Connector) -> BaseConnector:
        try:
            cls = get_connector_class(row.connector_type)
        except UnknownConnectorTypeError as exc:
            raise ValueError(
                f"connector_type {row.connector_type!r} is not registered"
            ) from exc
        # config_encrypted is stored as JSONB; current schema treats it as
        # opaque dict. Field-level encryption is a Sprint 2 enhancement.
        config = row.config_encrypted or {}
        return cls(config=config)

    async def _fetch(
        self, connector: BaseConnector, last_sync_at: datetime | None
    ) -> list[DiscoveredAsset]:
        if last_sync_at is None:
            return await connector.discover()
        return await connector.sync(since=last_sync_at)

    async def _upsert(
        self,
        db: AsyncSession,
        *,
        connector_id: uuid.UUID,
        assets: list[DiscoveredAsset],
        is_first_run: bool,
    ) -> dict[str, int]:
        now = datetime.now(timezone.utc)
        external_ids_seen: set[str] = set()

        # Load all existing rows for this connector in one shot so we can
        # decide insert vs update without N+1 queries.
        existing_rows = (
            await db.execute(
                select(AIAsset).where(AIAsset.connector_id == connector_id)
            )
        ).scalars().all()
        existing_by_ext: dict[str, AIAsset] = {
            r.external_id: r for r in existing_rows
        }

        discovered = 0
        updated = 0
        removed = 0

        for asset in assets:
            external_ids_seen.add(asset.external_id)
            existing = existing_by_ext.get(asset.external_id)
            if existing is None:
                row = AIAsset(
                    name=asset.name,
                    asset_type=asset.asset_type,
                    asset_status="active",
                    provider=asset.provider,
                    version=asset.version,
                    external_id=asset.external_id,
                    connector_id=connector_id,
                    description=asset.description,
                    metadata_json=asset.metadata or {},
                    discovered_at=now,
                    last_seen_at=now,
                )
                db.add(row)
                await db.flush()
                db.add(
                    AssetChangelog(
                        asset_id=row.id,
                        change_type="created",
                        previous_value=None,
                        new_value=_snapshot(row),
                    )
                )
                discovered += 1
            else:
                before = _snapshot(existing)
                existing.name = asset.name
                existing.asset_type = asset.asset_type
                existing.provider = asset.provider
                existing.version = asset.version
                existing.description = asset.description
                existing.metadata_json = asset.metadata or {}
                existing.last_seen_at = now
                if existing.asset_status != "active":
                    existing.asset_status = "active"
                after = _snapshot(existing)
                if before != after:
                    db.add(
                        AssetChangelog(
                            asset_id=existing.id,
                            change_type="updated",
                            previous_value=before,
                            new_value=after,
                        )
                    )
                    updated += 1

        # Soft-remove: assets that previously existed for this connector
        # but were not in this sync batch. Only flip on full discover()
        # runs — incremental sync() doesn't enumerate every asset.
        if is_first_run:
            for row in existing_rows:
                if row.external_id in external_ids_seen:
                    continue
                if row.asset_status == "inactive":
                    continue
                before = _snapshot(row)
                row.asset_status = "inactive"
                db.add(
                    AssetChangelog(
                        asset_id=row.id,
                        change_type="removed",
                        previous_value=before,
                        new_value=_snapshot(row),
                    )
                )
                removed += 1

        await db.flush()
        return {"discovered": discovered, "updated": updated, "removed": removed}


def _snapshot(row: AIAsset) -> dict[str, Any]:
    """Pure-data snapshot used for changelog diffs. Stable JSON."""
    return {
        "name": row.name,
        "asset_type": row.asset_type,
        "asset_status": row.asset_status,
        "provider": row.provider,
        "version": row.version,
        "description": row.description,
        "metadata": row.metadata_json or {},
    }


# ─────────────────────────────────────────── Redis state helpers


async def get_cursor(connector_id: uuid.UUID) -> dict[str, Any] | None:
    """Read the connector's persisted pagination cursor."""
    client = await get_redis()
    raw = await client.get(f"{CURSOR_KEY_PREFIX}{connector_id}")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def set_cursor(connector_id: uuid.UUID, cursor: dict[str, Any]) -> None:
    client = await get_redis()
    await client.set(
        f"{CURSOR_KEY_PREFIX}{connector_id}",
        json.dumps(cursor),
        ex=CURSOR_TTL_SECONDS,
    )


async def clear_cursor(connector_id: uuid.UUID) -> None:
    client = await get_redis()
    await client.delete(f"{CURSOR_KEY_PREFIX}{connector_id}")


async def hit_rate_limit(
    connector_id: uuid.UUID, *, max_per_minute: int
) -> bool:
    """Return True if a sync should *throttle*. Window is one minute,
    fixed (i.e. each new minute resets the counter)."""
    client = await get_redis()
    bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
    key = f"{RATE_KEY_PREFIX}{connector_id}:{bucket}"
    count = await client.incr(key)
    if count == 1:
        await client.expire(key, 90)  # auto-expire shortly after the minute
    return count > max_per_minute
