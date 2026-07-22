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
import pathlib

import pytest

pytestmark = pytest.mark.unit

_EXCEPTIONS = (
    pathlib.Path(__file__).resolve().parents[3] / "frontend" / "audit-exceptions.json"
)
_MAX_DAYS = 90
_REQUIRED = ("id", "package", "justification", "owner", "added", "expires")


def _entries() -> list[dict]:
    data = json.loads(_EXCEPTIONS.read_text())
    return data.get("exceptions", [])


@pytest.mark.skipif(not _EXCEPTIONS.exists(), reason="frontend not checked out")
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


@pytest.mark.skipif(not _EXCEPTIONS.exists(), reason="frontend not checked out")
def test_every_exception_is_well_formed() -> None:
    for e in _entries():
        missing = [f for f in _REQUIRED if not e.get(f)]
        assert not missing, f"exception {e.get('id', e)} missing fields: {missing}"
        assert len(e["justification"]) >= 40, (
            f"exception {e['id']}: justification must be grounded in real exposure, "
            "not a one-liner"
        )


@pytest.mark.skipif(not _EXCEPTIONS.exists(), reason="frontend not checked out")
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
