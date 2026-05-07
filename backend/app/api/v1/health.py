"""Health and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.redis_client import get_redis

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness — process is alive. Cheap; always returns 200."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(db: AsyncSession = Depends(get_db)) -> dict[str, str | bool]:
    """Readiness — every dependency the API needs to serve traffic is reachable."""
    checks: dict[str, str | bool] = {}

    try:
        result = await db.execute(text("SELECT 1"))
        checks["postgres"] = result.scalar() == 1
    except Exception as e:  # noqa: BLE001
        checks["postgres"] = False
        checks["postgres_error"] = str(e)

    try:
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = True
    except Exception as e:  # noqa: BLE001
        checks["redis"] = False
        checks["redis_error"] = str(e)

    overall_ok = all(v is True for k, v in checks.items() if not k.endswith("_error"))
    checks["status"] = "ok" if overall_ok else "degraded"
    return checks
