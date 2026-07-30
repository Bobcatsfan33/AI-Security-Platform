"""Tenant residency policy unit tests."""

import uuid
from types import SimpleNamespace

import pytest

from app.db.models.organization import Organization
from app.security import residency


def _org(region: str) -> Organization:
    return Organization(
        id=uuid.uuid4(),
        name="Resident tenant",
        slug=f"resident-{uuid.uuid4().hex[:8]}",
        data_region=region,
    )


@pytest.mark.unit
def test_matching_region_is_accepted(monkeypatch) -> None:
    monkeypatch.setattr(
        residency, "get_settings", lambda: SimpleNamespace(deployment_region="us-east-1")
    )
    org = _org("us-east-1")

    assert residency.enforce_organization_region(org, surface="/v1/assets") is org


@pytest.mark.unit
def test_mismatch_is_audited_without_raw_tenant_or_target_region(monkeypatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(
        residency, "get_settings", lambda: SimpleNamespace(deployment_region="us-east-1")
    )
    monkeypatch.setattr(
        residency,
        "log_event",
        lambda event, outcome, **kwargs: captured.update(
            {"event": event, "outcome": outcome, **kwargs}
        ),
    )
    org = _org("eu-west-1")

    with pytest.raises(residency.TenantRegionMismatchError):
        residency.enforce_organization_region(org, surface="/v1/assets")

    assert captured["tenant_id"] == "_global_"
    assert captured["detail"]["reason"] == "tenant_region_mismatch"
    assert captured["detail"]["deployment_region"] == "us-east-1"
    serialized = str(captured)
    assert str(org.id) not in serialized
    assert "eu-west-1" not in serialized
