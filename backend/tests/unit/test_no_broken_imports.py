"""Import guard — every module under ``app/`` must import cleanly.

Background: the v2.0 pivot (see ``app/db/models/__init__.py``) dropped the
governance models — ``connector_config``, ``evaluation``, ``finding``,
``test_case``, ``policy``, ``mcp`` — and their tables. A cluster of
governance/red-team modules imported those dropped models, so they failed on
import and were quarantined here (they were invisible to the rest of the suite
because nothing imports them, so their breakage never surfaced otherwise).

The governance revival brought every one of those models back (policies in
migration 0007; evaluations/findings/test_cases/connector_configs in 0008; the
MCP tables in 0009) plus the ``app.connectors.registry.build_connector``
factory, so the whole governance surface imports cleanly again and the
quarantine is now **empty**.

This guard still earns its keep as a ratchet:

* a NEW broken import (any live module that stops importing) fails the test, and
* if a module ever needs to be re-quarantined, add it to ``QUARANTINE`` with the
  dropped dependency as its reason — and the staleness test forces it back out
  the moment the dependency returns.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import app

pytestmark = pytest.mark.unit

# module path -> the dropped-model dependency that breaks its import.
# Empty: the governance revival (migrations 0007/0008/0009) restored every model
# the quarantined modules depended on. Keep this the last line of defence — a
# regression that breaks an import must be fixed, not re-added here without cause.
QUARANTINE: dict[str, str] = {}


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
