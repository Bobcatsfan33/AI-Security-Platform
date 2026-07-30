"""Enterprise IdP administration invariants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from app.api.v1.idp_admin import DirectorySyncConfig, _constraint_name

pytestmark = pytest.mark.unit


def test_directory_mapping_cannot_grant_owner_or_unknown_roles() -> None:
    for role in ("owner", "api_only", "superadmin"):
        with pytest.raises(ValidationError, match="may grant only"):
            DirectorySyncConfig(group_to_role_mapping={"Privileged": role})
    with pytest.raises(ValidationError):
        DirectorySyncConfig(default_role="owner")


def test_directory_mapping_accepts_only_provisionable_roles() -> None:
    config = DirectorySyncConfig(
        group_to_role_mapping={
            "Security": "admin",
            "Engineering": "analyst",
            "Everyone": "viewer",
        }
    )
    assert set(config.group_to_role_mapping.values()) == {
        "admin",
        "analyst",
        "viewer",
    }


def test_constraint_name_unwraps_async_driver_error() -> None:
    class DriverError(Exception):
        constraint_name = "uq_idp_configs_active_scim_per_org"

    wrapped = IntegrityError("statement", {}, RuntimeError("wrapper"))
    wrapped.orig.__cause__ = DriverError()
    assert _constraint_name(wrapped) == "uq_idp_configs_active_scim_per_org"


def test_unrelated_integrity_error_is_not_misclassified() -> None:
    wrapped = IntegrityError("statement", {}, RuntimeError("other"))
    assert _constraint_name(wrapped) is None
