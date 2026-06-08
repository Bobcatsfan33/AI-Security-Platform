"""Import guard — every module under ``app/`` must import cleanly, except the
explicitly documented v1-pivot quarantine set.

Background: the v2.0 pivot (see ``app/db/models/__init__.py``) dropped the
governance models — ``connector_config``, ``evaluation``, ``finding``,
``test_case``, ``policy``, ``mcp`` — and their tables. A cluster of
governance/red-team modules still import those dropped models, so they fail on
import. None are registered as routes; they sit on disk pending deliberate v2
revival (Red Teaming is the first — see the Phase-2 work).

The problem this test fixes: those modules are invisible to the rest of the
suite (nothing imports them), so their breakage never surfaced. This guard
imports *every* module under ``app/`` and pins the broken set:

* a NEW broken import (a live module that stops importing) fails the test, and
* a quarantined module that gets *revived* must be removed from the list, or
  the staleness test fails — keeping the manifest honest.

Each quarantine entry records the dropped model it depends on. Reviving a
feature = reintroduce its v2 model(s), repoint the module, drop it from
``QUARANTINE`` here.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import app

pytestmark = pytest.mark.unit

# module path -> the dropped-model dependency that breaks its import.
QUARANTINE: dict[str, str] = {
    "app.api.v1.compliance": "app.db.models.evaluation",
    "app.api.v1.evaluations": "app.db.models.evaluation",
    "app.api.v1.findings": "app.db.models.finding",
    "app.api.v1.mcp": "app.db.models.mcp",
    "app.api.v1.policies": "app.db.models.policy",
    "app.api.v1.reports": "app.db.models.evaluation",
    "app.api.v1.test_cases": "app.db.models.test_case",
    "app.api.v1.threat_intel": "app.db.models.finding",
    "app.compliance.evidence_pack": "app.db.models.evaluation",
    "app.evaluation.runner": "app.connectors.registry",
    "app.mcp.service": "app.db.models.mcp",
    "app.policy.cache": "app.db.models.policy",
    "app.threat_intel.engine": "app.db.models.finding",
}


def _all_app_modules() -> list[str]:
    return sorted(
        m.name for m in pkgutil.walk_packages(app.__path__, prefix="app.", onerror=lambda _n: None)
    )


def _broken_imports() -> dict[str, str]:
    broken: dict[str, str] = {}
    for name in _all_app_modules():
        try:
            importlib.import_module(name)
        except Exception as exc:
            broken[name] = f"{type(exc).__name__}: {exc}"
    return broken


def test_no_unexpected_broken_imports() -> None:
    """No module imports broken except the documented quarantine set."""
    broken = _broken_imports()
    unexpected = {name: err for name, err in broken.items() if name not in QUARANTINE}
    assert not unexpected, (
        "Modules that should import but don't (fix the import, or add to "
        f"QUARANTINE with a reason): {unexpected}"
    )


def test_quarantine_has_no_stale_entries() -> None:
    """Every quarantined module is still broken. Once a feature is revived its
    module imports cleanly — remove it from QUARANTINE so the list stays true."""
    revived: list[str] = []
    for name in QUARANTINE:
        try:
            importlib.import_module(name)
            revived.append(name)
        except Exception:
            pass
    assert not revived, f"These modules now import cleanly — remove them from QUARANTINE: {revived}"
