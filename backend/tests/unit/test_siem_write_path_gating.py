"""The SIEM tier gate on the WRITE path.

Sibling of test_siem_tier_gating.py, which covers the build/forward path. Both
halves are needed and they fail differently:

* the build path (``_build_one``) stops a config that predates the flag from
  forwarding — it is what makes the gate true;
* the write path stops new gated configuration from accumulating, and tells the
  operator why — it is what makes the gate usable.

The write path had no tests at all in the first cut, which is how the disable
carve-out shipped permitting strictly more than "disable": the check looked only
at ``payload.enabled`` and never at the stored record, so ``enabled: false`` was
a skeleton key that also let you rewrite a gated exporter's config, its secret
refs, or its type — staged inert, live the moment the flag flipped.

These call the validators directly rather than over HTTP: the router is not
mounted until Phase 1 (GAP-001). When it mounts, it inherits the full HTTP +
tenant-isolation treatment and these stay as the unit-level contract.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import HTTPException

from app.api.v1.siem import (
    ExporterCreate,
    _validate_exporter_tier_on_create,
    _validate_exporter_tier_on_update,
)
from app.core.config import get_settings

pytestmark = pytest.mark.unit

GATED = "sentinel"
ALLOWED = "splunk_hec"


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def extended_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLATFORM_ENABLE_SIEM_EXTENDED", "true")
    get_settings.cache_clear()


def _stored_gated() -> dict:
    """The legacy record the carve-out exists to serve: a Sentinel exporter
    configured before the gate landed."""
    return {
        "type": GATED,
        "name": "legacy-sentinel",
        "config": {"workspace_id": "w", "shared_key": "env:SENTINEL_KEY"},
        "enabled": True,
    }


def _payload(stored: dict, **overrides) -> ExporterCreate:
    return ExporterCreate(**{**stored, **overrides})


# ─────────────────────────────────────────── create: no carve-out at all


def test_create_rejects_a_gated_type() -> None:
    with pytest.raises(HTTPException) as exc:
        _validate_exporter_tier_on_create(_payload(_stored_gated()))

    assert exc.value.status_code == 400
    assert "PLATFORM_ENABLE_SIEM_EXTENDED" in exc.value.detail


def test_create_rejects_a_gated_type_even_when_disabled() -> None:
    """THE create test. `enabled: false` is not a way in.

    Otherwise anyone could stage Sentinel/Datadog/Chronicle exporters on a
    deployment where the flag is off — inert and unreviewed — and every one of
    them goes live at once the day the flag flips. Frozen has to mean you cannot
    build a backlog behind the flag.
    """
    with pytest.raises(HTTPException) as exc:
        _validate_exporter_tier_on_create(_payload(_stored_gated(), enabled=False))

    assert exc.value.status_code == 400


def test_create_accepts_a_tier_b_type() -> None:
    _validate_exporter_tier_on_create(
        ExporterCreate(type=ALLOWED, name="prod", config={"url": "u", "token": "env:T"})
    )


def test_create_accepts_a_gated_type_once_pulled_forward(extended_enabled: None) -> None:
    _validate_exporter_tier_on_create(_payload(_stored_gated()))


# ─────────────────────────────────────────── update: judged against the record


def test_update_accepts_disabling_a_gated_exporter() -> None:
    """The carve-out's whole purpose: turn the legacy config off without
    deleting it, no flag required."""
    stored = _stored_gated()

    _validate_exporter_tier_on_update(_payload(stored, enabled=False), stored)


def test_update_rejects_re_enabling_a_gated_exporter() -> None:
    stored = {**_stored_gated(), "enabled": False}

    with pytest.raises(HTTPException) as exc:
        _validate_exporter_tier_on_update(_payload(stored, enabled=True), stored)

    assert exc.value.status_code == 400
    assert "PLATFORM_ENABLE_SIEM_EXTENDED" in exc.value.detail


def test_update_rejects_rewriting_a_gated_exporters_config_while_disabling_it() -> None:
    """THE update test. `enabled: false` must not be a skeleton key.

    A check that looked only at payload.enabled would accept this: the config
    and its secret ref are rewritten, the write is "a disable", and the new
    configuration sits inert until the flag flips — at which point it forwards
    to wherever this edit pointed it. The gate would be guarding the wrong noun.
    """
    stored = _stored_gated()
    rewritten = _payload(
        stored,
        enabled=False,
        config={"workspace_id": "attacker", "shared_key": "env:OTHER_KEY"},
    )

    with pytest.raises(HTTPException) as exc:
        _validate_exporter_tier_on_update(rewritten, stored)

    assert exc.value.status_code == 400
    assert "Only 'enabled' may be changed" in exc.value.detail


def test_update_rejects_changing_a_gated_exporters_type_while_disabling_it() -> None:
    stored = _stored_gated()

    with pytest.raises(HTTPException):
        _validate_exporter_tier_on_update(
            _payload(stored, enabled=False, type="datadog", config={"api_key": "env:DD"}),
            stored,
        )


def test_update_rejects_migrating_a_gated_exporter_to_an_allowed_type() -> None:
    """Deliberate: delete-and-create instead, so the replacement passes create
    validation on its own merits rather than inheriting a grandfathered slot."""
    stored = _stored_gated()

    with pytest.raises(HTTPException):
        _validate_exporter_tier_on_update(
            _payload(stored, enabled=False, type=ALLOWED, config={"url": "u", "token": "env:T"}),
            stored,
        )


def test_update_of_a_stored_allowed_type_follows_normal_rules() -> None:
    """Nothing gated is being preserved, so the payload stands on its own."""
    stored = {
        "type": ALLOWED,
        "name": "prod",
        "config": {"url": "u", "token": "env:T"},
        "enabled": True,
    }

    _validate_exporter_tier_on_update(_payload(stored, config={"url": "v", "token": "env:T"}), stored)

    with pytest.raises(HTTPException):
        # …and it cannot become a gated type by the back door.
        _validate_exporter_tier_on_update(
            _payload(stored, type=GATED, config={"workspace_id": "w", "shared_key": "env:K"}),
            stored,
        )


def test_update_of_a_gated_exporter_is_unrestricted_once_pulled_forward(
    extended_enabled: None,
) -> None:
    stored = _stored_gated()

    _validate_exporter_tier_on_update(
        _payload(stored, config={"workspace_id": "new", "shared_key": "env:K2"}), stored
    )


def test_a_stored_record_with_an_unknown_type_is_not_treated_as_gated() -> None:
    """A corrupted or hand-edited JSONB record naming a type we do not
    recognise is not a legacy gated config, so the payload is judged on its own
    merits — and crucially the operator is not told to set
    PLATFORM_ENABLE_SIEM_EXTENDED, which could never un-gate a type that does
    not exist.
    """
    stored = {"type": "sentinal", "name": "typo", "config": {}, "enabled": True}

    # Replacing it with a Tier B type is fine: nothing gated is being preserved.
    _validate_exporter_tier_on_update(
        ExporterCreate(type=ALLOWED, name="typo", config={"url": "u", "token": "env:T"}),
        stored,
    )

    # …and it still cannot become a gated type by the back door.
    with pytest.raises(HTTPException) as exc:
        _validate_exporter_tier_on_update(
            ExporterCreate(
                type=GATED, name="typo", config={"workspace_id": "w", "shared_key": "env:K"}
            ),
            stored,
        )

    assert "PLATFORM_ENABLE_SIEM_EXTENDED" in exc.value.detail


def test_a_stored_record_without_enabled_is_treated_as_enabled() -> None:
    """Configs written before the field exists have no `enabled` key; disabling
    one must still be the accepted write."""
    stored = _stored_gated()
    del stored["enabled"]

    _validate_exporter_tier_on_update(_payload(stored, enabled=False), stored)
