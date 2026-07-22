"""Secret refs are resolved on the SEND path (F1).

The bug this guards: create-time validation resolved a ref only to prove it
resolvable, then stored the ref — and ``_build_one`` handed that stored ref
straight to the exporter constructor. So Splunk received
``Authorization: Splunk env:SPLUNK_TOKEN`` (the literal ref), and the "usable
out of the box" Tier B pair could not authenticate to a real SIEM. Validating
where the config is written but not resolving where the bytes leave is the exact
anti-pattern the SIEM module's own doctrine warns against.

These prove the resolved value reaches the outbound exporter, the stored config
still carries the ref (so it is never persisted in the clear), and an
unresolvable ref drops that one exporter loudly rather than raising.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

from app.security import secrets as secrets_module
from app.security.secrets import SecretResolutionError
from app.siem.exporters import build_exporters

pytestmark = pytest.mark.unit

RESOLVED = "the-real-splunk-token"


class _StubResolver:
    """Resolves ``env:KNOWN`` to a fixed secret; anything else raises, like the
    real resolver does for a missing var."""

    def resolve(self, reference: str) -> str:
        if reference == "env:KNOWN":
            return RESOLVED
        raise SecretResolutionError(f"cannot resolve {reference!r}")


@pytest.fixture(autouse=True)
def _stub_resolver() -> Iterator[None]:
    original = secrets_module.get_resolver()
    secrets_module.set_resolver(_StubResolver())
    try:
        yield
    finally:
        secrets_module.set_resolver(original)


def _splunk(token_ref: str) -> dict:
    return {
        "type": "splunk_hec",
        "name": "prod",
        "config": {"url": "https://splunk.example.com", "token": token_ref},
    }


def test_outbound_exporter_carries_the_resolved_secret() -> None:
    """THE test: the built exporter authenticates with the real token, not the
    ref string."""
    config = _splunk("env:KNOWN")

    exporters = build_exporters([config])

    assert len(exporters) == 1
    # The Splunk exporter stores the token it will send in the Authorization
    # header. It must be the resolved value.
    assert exporters[0]._token == RESOLVED  # type: ignore[attr-defined]
    assert exporters[0]._token != "env:KNOWN"  # type: ignore[attr-defined]


def test_stored_config_still_carries_the_ref_not_the_secret() -> None:
    """Resolution must not mutate the stored config: the JSONB column keeps the
    ref, so the secret is never persisted in the clear."""
    config = _splunk("env:KNOWN")

    build_exporters([config])

    assert config["config"]["token"] == "env:KNOWN", "the input/stored config was mutated"


def test_unresolvable_ref_drops_only_that_exporter(caplog) -> None:
    """A ref that fails to resolve (rotated var, unmounted vault) drops that one
    exporter — it does not raise and take the forwarder's whole batch down."""
    good = {
        "type": "elastic",
        "name": "es",
        "config": {"url": "https://es.example.com", "index": "aisp"},
    }  # elastic here has no secret field set → nothing to resolve
    broken = _splunk("env:ROTATED_AWAY")

    with caplog.at_level(logging.ERROR):
        exporters = build_exporters([good, broken])

    names = {e.name for e in exporters}
    assert names == {"es"}, "the broken exporter must be dropped, the good one kept"
    assert "siem_secret_unresolved" in caplog.text, "the drop must be logged loudly"


def test_a_batch_of_all_broken_refs_builds_nothing_without_raising() -> None:
    """The forwarder must survive an org whose every secret rotated away."""
    exporters = build_exporters([_splunk("env:GONE_1"), _splunk("env:GONE_2")])
    assert exporters == []


def test_the_failure_log_contains_no_secret(caplog) -> None:
    """N2: the drop-on-unresolvable log must never carry the secret ref, the
    resolved value, or the resolver's message (which a backend can fill with a
    vault path or the secret itself). Pins the property the _build_one refactor
    established structurally."""
    import logging

    # A resolver whose EXCEPTION MESSAGE embeds a secret-looking string, to prove
    # the message never reaches the log.
    class _LeakyResolver:
        def resolve(self, reference: str) -> str:
            raise SecretResolutionError(f"backend echoed secret VERY-SECRET-VALUE for {reference}")

    secrets_module.set_resolver(_LeakyResolver())
    try:
        with caplog.at_level(logging.ERROR):
            assert build_exporters([_splunk("env:ANYTHING")]) == []
    finally:
        secrets_module.set_resolver(_StubResolver())

    text = caplog.text
    assert "siem_secret_unresolved" in text, "the drop must still be logged"
    assert "VERY-SECRET-VALUE" not in text, "the resolver's message leaked into the log"
    assert "env:ANYTHING" not in text, "the secret ref leaked into the log"
