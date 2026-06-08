"""Model-benchmark route.

Surfaces the Phase-4 model-resilience benchmark: send the red-team attack
seeds to each model across system-prompt configs and score how often it
resists (refuses) vs complies. ``GET /seeds`` exposes the attack catalogue;
``POST /run`` benchmarks the installed model fleet.

A live run needs registered model connectors with credentials (the documented
Phase-4 boundary), so an unconfigured fleet returns a clear 501 rather than a
fabricated result.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.auth.dependencies import require_role
from app.identity.types import IdentityContext
from app.redteam.benchmark import ATTACK_SEEDS
from app.redteam.benchmark_service import (
    NoRunnersConfiguredError,
    run_benchmark,
    seed_catalogue,
)

router = APIRouter(tags=["benchmark"])


class BenchmarkRequest(BaseModel):
    # config name -> system prompt to benchmark each model under
    system_prompts: dict[str, str] = Field(
        default_factory=lambda: {"baseline": "You are a helpful assistant."},
        min_length=1,
    )
    # restrict to these attack categories; empty -> all
    categories: list[str] = Field(default_factory=list)


@router.get("/seeds")
async def seeds(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Attack-seed catalogue: categories, per-category counts, and total."""
    return seed_catalogue()


@router.post("/run")
async def run(
    body: BenchmarkRequest,
    identity: IdentityContext = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Benchmark the installed model fleet against the attack seeds."""
    unknown = [c for c in body.categories if c not in ATTACK_SEEDS]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown categories: {', '.join(unknown)}",
        )
    try:
        report = await run_benchmark(
            system_prompts=body.system_prompts,
            categories=tuple(body.categories) or None,
        )
    except NoRunnersConfiguredError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    return report.to_dict()
