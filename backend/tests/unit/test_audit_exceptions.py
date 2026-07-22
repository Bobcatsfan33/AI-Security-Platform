"""The frontend npm-audit exceptions must stay honest (policy: docs/GAPS.md).

frontend/scripts/audit-gate.mjs enforces these at the Security gate. This test
is the fast local signal — and, crucially, the one that makes an EXPIRED
exception fail `pytest`, not just CI: an expired exception is a red gate, never a
stale ignore. It lives in the Python suite because that is this repo's test
runner (the frontend has none — GAP-015); it reads the same JSON the gate does.

It is deliberately time-dependent. A test that passes today and fails the day an
exception lapses is the mechanism working, not flaking.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib

import pytest

pytestmark = pytest.mark.unit

_EXCEPTIONS = (
    pathlib.Path(__file__).resolve().parents[3] / "frontend" / "audit-exceptions.json"
)
_MAX_DAYS = 90
# 30 is the default; anything longer must justify itself in the entry.
_DEFAULT_DAYS = 30
_REQUIRED = ("id", "package", "justification", "owner", "added", "expires")


@pytest.fixture(autouse=True)
def _require_exceptions_file() -> None:
    """Fail loudly if the file is missing, rather than skip.

    A test that reports green exactly when it stops being checked is the known
    failure mode (#65 removed this same silent-skip from the frontend parity
    test). If the frontend is deliberately not checked out, say so via
    ASP_BACKEND_ONLY=1 — an explicit opt-out, not a silent one.
    """
    if _EXCEPTIONS.exists():
        return
    if os.environ.get("ASP_BACKEND_ONLY") == "1":
        pytest.skip("ASP_BACKEND_ONLY=1: frontend deliberately not checked out")
    pytest.fail(
        f"{_EXCEPTIONS} is missing, so the npm-audit exception policy is unchecked. "
        "If this is an intentional backend-only run, set ASP_BACKEND_ONLY=1 to skip "
        "explicitly rather than silently."
    )


def _entries() -> list[dict]:
    data = json.loads(_EXCEPTIONS.read_text())
    return data.get("exceptions", [])


def test_no_exception_is_expired() -> None:
    """The load-bearing one: an expired exception fails the build."""
    today = datetime.date.today()
    expired = [
        f"{e['id']} ({e['package']}) expired {e['expires']}"
        for e in _entries()
        if datetime.date.fromisoformat(e["expires"]) < today
    ]
    assert not expired, (
        "Expired npm-audit exceptions — fix the advisory or renew with fresh "
        f"justification and a new expiry: {expired}"
    )


def test_every_exception_is_well_formed() -> None:
    for e in _entries():
        missing = [f for f in _REQUIRED if not e.get(f)]
        assert not missing, f"exception {e.get('id', e)} missing fields: {missing}"
        assert len(e["justification"]) >= 40, (
            f"exception {e['id']}: justification must be grounded in real exposure, "
            "not a one-liner"
        )


def test_a_window_over_the_default_carries_its_own_reason() -> None:
    """30 is the default; a longer window must say why IN THE ENTRY.

    Without this, the first exception took the 90-day max and the "30 default"
    became 30-in-name-only. Requiring a `window_reason` for anything over 30
    keeps the default meaningful — you can still go to 90, but you have to argue
    for it where the next reader will see it.
    """
    for e in _entries():
        added = datetime.date.fromisoformat(e["added"])
        expires = datetime.date.fromisoformat(e["expires"])
        span = (expires - added).days
        if span > _DEFAULT_DAYS:
            assert e.get("window_reason"), (
                f"exception {e['id']}: window is {span}d (>{_DEFAULT_DAYS} default) "
                "but has no 'window_reason' explaining why it needs longer"
            )


def test_no_exception_window_exceeds_the_max() -> None:
    """30 days default, 90 max. A longer window is a slow ignore wearing an
    expiry."""
    for e in _entries():
        added = datetime.date.fromisoformat(e["added"])
        expires = datetime.date.fromisoformat(e["expires"])
        span = (expires - added).days
        assert 0 < span <= _MAX_DAYS, (
            f"exception {e['id']}: window is {span}d (must be 1..{_MAX_DAYS})"
        )
