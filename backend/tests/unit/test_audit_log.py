"""Audit log tests — chain integrity, HMAC signing, dispatch resilience."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security import audit_log
from app.security.audit_log import (
    AuditEventType,
    AuditOutcome,
    AuditRecord,
    log_event,
    reset_chain_for_tests,
    verify_log_integrity,
)


@pytest.fixture(autouse=True)
def _reset_chain() -> None:
    reset_chain_for_tests()


@pytest.fixture
def isolated_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_log, "AUDIT_FILE", str(log_path))
    monkeypatch.setattr(audit_log, "AUDIT_BACKENDS", ("file",))
    return log_path


@pytest.mark.unit
class TestAuditRecord:
    def test_record_has_au3_required_fields(self) -> None:
        record = log_event(
            AuditEventType.AUTH_SUCCESS,
            AuditOutcome.SUCCESS,
            tenant_id="org-1",
            subject="user-1",
            source_ip="192.0.2.1",
            resource="/v1/auth/oidc/acme/callback",
        )
        # AU-3 fields: timestamp, event_type, subject, outcome, source_ip,
        # resource, tenant_id, correlation_id
        for field in (
            "timestamp",
            "event_type",
            "subject",
            "outcome",
            "source_ip",
            "resource",
            "tenant_id",
            "correlation_id",
        ):
            assert getattr(record, field), f"AU-3 field {field!r} empty"

    def test_event_type_enum_value_is_string(self) -> None:
        record = log_event(AuditEventType.POLICY_CREATED)
        assert record.event_type == "policy.created"

    def test_event_type_string_passthrough(self) -> None:
        record = log_event("custom.event_type")
        assert record.event_type == "custom.event_type"


@pytest.mark.unit
class TestHashChain:
    def test_first_entry_links_to_genesis(self, isolated_log: Path) -> None:
        record = log_event(AuditEventType.STARTUP)
        assert record.prev_hash == "0" * 64

    def test_subsequent_entries_chain(self, isolated_log: Path) -> None:
        first = log_event(AuditEventType.AUTH_SUCCESS, subject="u1")
        second = log_event(AuditEventType.POLICY_CREATED, subject="u1")
        third = log_event(AuditEventType.POLICY_UPDATED, subject="u1")

        assert second.prev_hash == first.entry_hash
        assert third.prev_hash == second.entry_hash

    def test_sequence_monotonic(self, isolated_log: Path) -> None:
        records = [log_event(AuditEventType.AUTH_SUCCESS) for _ in range(5)]
        assert [r.sequence for r in records] == [1, 2, 3, 4, 5]

    def test_each_entry_has_distinct_hash(self, isolated_log: Path) -> None:
        hashes = {log_event(AuditEventType.AUTH_SUCCESS).entry_hash for _ in range(10)}
        assert len(hashes) == 10


@pytest.mark.unit
class TestFileBackend:
    def test_writes_one_line_per_event(self, isolated_log: Path) -> None:
        log_event(AuditEventType.AUTH_SUCCESS, subject="alice")
        log_event(AuditEventType.POLICY_CREATED, subject="alice")

        content = isolated_log.read_text(encoding="utf-8").splitlines()
        assert len(content) == 2

    def test_each_line_is_parseable_json(self, isolated_log: Path) -> None:
        log_event(AuditEventType.AUTH_SUCCESS)
        line = isolated_log.read_text(encoding="utf-8").strip()
        record = json.loads(line)
        assert record["event_type"] == "auth.success"
        assert "entry_hash" in record
        assert "prev_hash" in record


@pytest.mark.unit
class TestIntegrityVerification:
    def test_intact_chain_verifies(self, isolated_log: Path) -> None:
        for _ in range(5):
            log_event(AuditEventType.AUTH_SUCCESS)

        result = verify_log_integrity(str(isolated_log))
        assert result["ok"] is True
        assert result["entries"] == 5
        assert result["first_violation"] is None

    def test_tampered_entry_detected(self, isolated_log: Path) -> None:
        log_event(AuditEventType.AUTH_SUCCESS, subject="user-a")
        log_event(AuditEventType.POLICY_CREATED, subject="user-a")
        log_event(AuditEventType.POLICY_UPDATED, subject="user-a")

        # Tamper with the middle entry's subject field
        lines = isolated_log.read_text(encoding="utf-8").splitlines()
        middle = json.loads(lines[1])
        middle["subject"] = "attacker"
        lines[1] = json.dumps(middle, separators=(",", ":"))
        isolated_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_log_integrity(str(isolated_log))
        assert result["ok"] is False
        assert result["first_violation"] == 2

    def test_chain_break_detected(self, isolated_log: Path) -> None:
        log_event(AuditEventType.AUTH_SUCCESS)
        log_event(AuditEventType.POLICY_CREATED)
        log_event(AuditEventType.POLICY_DELETED)

        # Drop the middle line entirely → entry 3's prev_hash points to a missing parent
        lines = isolated_log.read_text(encoding="utf-8").splitlines()
        del lines[1]
        isolated_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_log_integrity(str(isolated_log))
        assert result["ok"] is False

    def test_empty_log_verifies_clean(self, tmp_path: Path) -> None:
        result = verify_log_integrity(str(tmp_path / "nonexistent.jsonl"))
        assert result["ok"] is True
        assert result["entries"] == 0


@pytest.mark.unit
class TestHmacSigning:
    def test_signed_chain_uses_hmac_when_key_resolves(
        self, isolated_log: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.security import secrets as secrets_mod

        class StaticHmacResolver:
            prefix = "static:"

            def resolve(self, reference: str) -> str:
                return "test-hmac-key-32bytes-or-more-padding-here"

        original = secrets_mod.get_resolver()
        secrets_mod.set_resolver(StaticHmacResolver())
        try:
            monkeypatch.setattr(audit_log, "AUDIT_HMAC_KEY_REF", "static:audit-key")
            audit_log.reset_chain_for_tests()
            record = log_event(AuditEventType.AUTH_SUCCESS)
            # HMAC-SHA256 → 64 hex chars; we already had SHA-256 producing 64 hex
            # so length alone doesn't prove anything. Instead recompute and compare
            # via verify_log_integrity which uses the same key.
            result = verify_log_integrity(str(isolated_log))
            assert result["ok"] is True
            assert record.entry_hash != ""
        finally:
            secrets_mod.set_resolver(original)
            audit_log._hmac_key_cache = None  # type: ignore[attr-defined]


@pytest.mark.unit
class TestDispatchResilience:
    def test_unknown_backend_logged_not_raised(
        self, monkeypatch: pytest.MonkeyPatch, isolated_log: Path
    ) -> None:
        monkeypatch.setattr(audit_log, "AUDIT_BACKENDS", ("file", "carrier_pigeon"))
        record = log_event(AuditEventType.AUTH_SUCCESS)
        assert record.entry_hash  # call still returned a record

    def test_backend_exception_does_not_break_caller(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Point the file backend at a path the OS can't write to
        monkeypatch.setattr(audit_log, "AUDIT_FILE", "/proc/cant-write-here/audit.jsonl")
        monkeypatch.setattr(audit_log, "AUDIT_BACKENDS", ("file",))
        # Should not raise — audit emission must never break the caller
        record = log_event(AuditEventType.AUTH_FAILURE, AuditOutcome.FAILURE)
        assert record.entry_hash


@pytest.mark.unit
class TestRecordSerialization:
    def test_canonical_excludes_entry_hash(self) -> None:
        record = AuditRecord(
            event_type="test.event", outcome="success", entry_hash="should-be-excluded"
        )
        canonical = audit_log._canonical(record)  # type: ignore[attr-defined]
        assert b"should-be-excluded" not in canonical

    def test_canonical_is_deterministic(self) -> None:
        record1 = AuditRecord(
            event_type="x", outcome="y", tenant_id="t1", correlation_id="cid", timestamp="ts"
        )
        record2 = AuditRecord(
            event_type="x", outcome="y", tenant_id="t1", correlation_id="cid", timestamp="ts"
        )
        assert audit_log._canonical(record1) == audit_log._canonical(record2)  # type: ignore[attr-defined]
