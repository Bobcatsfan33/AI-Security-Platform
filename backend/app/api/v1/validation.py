"""Detection-efficacy validation route.

Runs the purple-team replay suite (synthetic multi-agent attacks through the
real EPA stack) on demand and returns the measured detection + false-positive
rates. Lets operators verify detection efficacy without external tooling — and
re-verify after a pattern/threshold change.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.auth.dependencies import require_role
from app.identity.types import IdentityContext
from app.validation.harness import run_suite

router = APIRouter(tags=["validation"])


@router.get("/efficacy")
async def efficacy(
    identity: IdentityContext = Depends(require_role("admin")),
) -> dict[str, Any]:
    suite = await run_suite()
    return suite.summary()
