"""Static guarantees for tenant isolation (Wall 1 wiring) — no DB required.

The behavioural proofs (cross-tenant reads filtered, fail-closed, RLS) live in
tests/integration/test_tenant_guard.py. These tests guard the *wiring*: that
every tenant model is marked, and that install/remove toggles the listener.
"""

from __future__ import annotations

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.db import models  # noqa: F401 — ensure every model is imported/mapped
from app.db.base import Base
from app.db.tenancy import TenantScoped, _tenant_guard, install_tenant_guard

pytestmark = pytest.mark.unit


def test_every_tenant_model_is_marked():
    """Any mapped model with an org_id column MUST be TenantScoped.

    This is the safety net the roadmap demands: a future tenant table cannot
    ship unmarked (and therefore unguarded) without failing this test.
    """
    unmarked = [
        m.__name__
        for m in Base.__subclasses__()
        if hasattr(m, "org_id") and not issubclass(m, TenantScoped) and m.__name__ != "Organization"
    ]
    assert unmarked == [], f"models with org_id missing TenantScoped: {unmarked}"


def test_expected_models_are_scoped():
    """The 13 known tenant models are all marked (positive assertion)."""
    scoped = {m.__name__ for m in Base.__subclasses__() if issubclass(m, TenantScoped)}
    expected = {
        "AIAsset",
        "ApiKey",
        "AssetChangelog",
        "AssetRelationship",
        "AssetTag",
        "Connector",
        "Deployment",
        "IdpConfig",
        "Owner",
        "RedTeamCampaign",
        "RedTeamFinding",
        "SyncJob",
        "User",
    }
    assert expected <= scoped


def test_test_case_is_the_only_global_readable_model():
    """``__tenant_global_readable__`` relaxes the Wall-1 guard to also expose a
    model's shared ``org_id IS NULL`` rows. Only TestCase's global library needs
    that today — this ratchet forces any future addition to be deliberate."""
    global_readable = {
        m.__name__
        for m in Base.__subclasses__()
        if issubclass(m, TenantScoped) and getattr(m, "__tenant_global_readable__", False)
    }
    assert global_readable == {"TestCase"}, global_readable


def test_organization_is_not_scoped():
    """The tenant root must NOT be guarded (it has no org_id)."""
    from app.db.models.organization import Organization

    assert not issubclass(Organization, TenantScoped)


def test_exactly_two_sanctioned_bypass_sites():
    """The ORM-guard escape hatch may be used at exactly two audited sites:
    API-key resolution and SCIM IdP resolution. Grep-enforced so a third,
    unreviewed bypass cannot slip in."""
    import pathlib

    app_dir = pathlib.Path(__file__).resolve().parents[2] / "app"
    needle = '"bypass_tenant_guard": True'
    hits = sorted(
        f"{p.relative_to(app_dir)}" for p in app_dir.rglob("*.py") if needle in p.read_text()
    )
    assert hits == ["auth/api_key_service.py", "scim/auth.py"], hits


def test_install_tenant_guard_is_idempotent():
    """Installing twice registers exactly one listener; removable for test
    hygiene."""
    was_present = event.contains(Session, "do_orm_execute", _tenant_guard)
    try:
        install_tenant_guard()
        install_tenant_guard()
        assert event.contains(Session, "do_orm_execute", _tenant_guard)
    finally:
        if not was_present:
            event.remove(Session, "do_orm_execute", _tenant_guard)
