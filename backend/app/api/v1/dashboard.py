"""Dashboard summary — top-level KPIs for the executive view."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.ai_asset import AIAsset
from app.db.session import get_db
from app.identity.types import IdentityContext

router = APIRouter(tags=["dashboard"])


class CountByKey(BaseModel):
    key: str
    count: int


class DashboardSummary(BaseModel):
    total_assets: int
    active_assets: int
    inactive_assets: int
    by_type: list[CountByKey]
    by_provider: list[CountByKey]
    discovered_last_24h: int
    discovered_last_7d: int
    discovered_last_30d: int
    unowned_count: int
    unmonitored_count: int


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> DashboardSummary:
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)
    cutoff_30d = now - timedelta(days=30)

    total = int(
        (await db.execute(select(func.count()).select_from(AIAsset)))
        .scalar_one() or 0
    )
    active = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AIAsset)
                .where(AIAsset.asset_status == "active")
            )
        ).scalar_one()
        or 0
    )

    type_rows = (
        await db.execute(
            select(AIAsset.asset_type, func.count())
            .group_by(AIAsset.asset_type)
            .order_by(func.count().desc())
        )
    ).all()
    provider_rows = (
        await db.execute(
            select(AIAsset.provider, func.count())
            .group_by(AIAsset.provider)
            .order_by(func.count().desc())
            .limit(20)
        )
    ).all()

    def _count_since(cutoff: datetime) -> int:
        return int(
            db.run_sync  # type: ignore[attr-defined]
            if False
            else 0
        )

    last_24h = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AIAsset)
                .where(AIAsset.discovered_at >= cutoff_24h)
            )
        ).scalar_one()
        or 0
    )
    last_7d = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AIAsset)
                .where(AIAsset.discovered_at >= cutoff_7d)
            )
        ).scalar_one()
        or 0
    )
    last_30d = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AIAsset)
                .where(AIAsset.discovered_at >= cutoff_30d)
            )
        ).scalar_one()
        or 0
    )
    unowned = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AIAsset)
                .where(AIAsset.owner_id.is_(None))
                .where(AIAsset.asset_status == "active")
            )
        ).scalar_one()
        or 0
    )
    # An asset counts as "unmonitored" when nothing has touched its
    # ``last_seen_at`` in the last 30 days. Runtime monitoring is
    # Track 2 and folds telemetry into this same field.
    stale_cutoff = now - timedelta(days=30)
    unmonitored = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AIAsset)
                .where(AIAsset.asset_status == "active")
                .where(AIAsset.last_seen_at < stale_cutoff)
            )
        ).scalar_one()
        or 0
    )

    return DashboardSummary(
        total_assets=total,
        active_assets=active,
        inactive_assets=max(0, total - active),
        by_type=[CountByKey(key=str(t or "unknown"), count=int(c)) for t, c in type_rows],
        by_provider=[
            CountByKey(key=str(p or "unknown"), count=int(c)) for p, c in provider_rows
        ],
        discovered_last_24h=last_24h,
        discovered_last_7d=last_7d,
        discovered_last_30d=last_30d,
        unowned_count=unowned,
        unmonitored_count=unmonitored,
    )
