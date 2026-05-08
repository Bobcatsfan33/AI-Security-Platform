"""Tamper-evident audit log — hash-chained, multi-backend.

NIST 800-53 Rev5: AU-2 (audit events), AU-3 (content of audit records),
AU-9 (protection of audit information), AU-12 (audit record generation).

Origin: ported from TokenDNA ``modules/security/audit_log.py``. Adapted to
the platform's async runtime, structlog, and secrets resolver.

Design
------
Every security-relevant operation emits an :class:`AuditRecord` containing
AU-3 fields (timestamp, event_type, subject, outcome, source_ip, resource,
tenant_id, correlation_id) plus a ``prev_hash`` linking to the previous
entry. Each entry's ``entry_hash`` is HMAC-SHA256 of the canonical JSON
when an HMAC key is configured, plain SHA-256 otherwise (dev only).

Storage backends are pluggable. Sprint 1B ships:
    file  — append-only JSONL, fsync'd on every write (default)
    redis — RPUSH to a per-tenant per-day list (low-latency, in-memory)
    siem  — POST to a webhook with HMAC signature

Backends are selectable per-deployment via ``AUDIT_BACKEND`` (comma-
separated to use multiple, e.g. ``file,siem``).

Integrity verification (:func:`verify_log_integrity`) walks the file and
confirms every hash matches its computed value. Run nightly. A chain break
indicates tampering.

The HMAC key is resolved through the secrets module, so production
deployments can store it in AWS Secrets Manager / Vault rather than env.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import structlog

from app.security.secrets import SecretResolutionError, get_resolver

logger = structlog.get_logger("platform.audit")


# ────────────────────────────────────────────────────────── Configuration

AUDIT_BACKENDS: tuple[str, ...] = tuple(
    b.strip().lower()
    for b in os.getenv("AUDIT_BACKEND", "file").split(",")
    if b.strip()
)
AUDIT_FILE: str = os.getenv("AUDIT_LOG_PATH", "./var/audit/audit.jsonl")
AUDIT_HMAC_KEY_REF: str = os.getenv("AUDIT_HMAC_KEY_REF", "")
AUDIT_WEBHOOK: str = os.getenv("AUDIT_SIEM_WEBHOOK_URL", "")
AUDIT_REDIS_TTL_DAYS: int = int(os.getenv("AUDIT_REDIS_TTL_DAYS", "90"))


# ────────────────────────────────────────────────────────── Event taxonomy


class AuditEventType(str, Enum):
    """AU-2 event taxonomy. Sprint 1B core set; add new entries as
    additional security-bearing operations are introduced."""

    # Authentication & session
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_TOKEN_ISSUED = "auth.token.issued"
    AUTH_TOKEN_REVOKED = "auth.token.revoked"
    AUTH_TOKEN_REFRESHED = "auth.token.refreshed"
    AUTH_REFRESH_REUSE_DETECTED = "auth.refresh.reuse_detected"
    SESSION_TERMINATED = "session.terminated"

    # Access control
    ACCESS_DENIED = "access.denied"

    # Policy lifecycle (Sprint 1)
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
    POLICY_DELETED = "policy.deleted"

    # IDP configuration lifecycle
    IDP_CONFIG_CREATED = "idp.config.created"
    IDP_CONFIG_UPDATED = "idp.config.updated"
    IDP_CONFIG_DELETED = "idp.config.deleted"

    # Tenant / user lifecycle
    TENANT_CREATED = "tenant.created"
    USER_PROVISIONED = "user.provisioned"

    # API keys
    API_KEY_CREATED = "apikey.created"
    API_KEY_REVOKED = "apikey.revoked"

    # System
    CONFIG_CHANGED = "system.config_changed"
    STARTUP = "system.startup"
    SHUTDOWN = "system.shutdown"
    INTEGRITY_VERIFIED = "system.integrity_verified"
    INTEGRITY_VIOLATION = "system.integrity_violation"


class AuditOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# ────────────────────────────────────────────────────────── Record


@dataclass
class AuditRecord:
    """AU-3 compliant audit record."""

    event_type: str
    outcome: str
    tenant_id: str = "_global_"
    subject: str = "system"        # user_id, api_key_id, or "system"
    source_ip: str = "0.0.0.0"
    resource: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: _iso_now())
    sequence: int = 0
    prev_hash: str = ""
    entry_hash: str = ""


def _iso_now() -> str:
    ms = int(time.time() * 1000) % 1000
    return time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{ms:03d}Z"


def _canonical(record: AuditRecord) -> bytes:
    """Deterministic JSON for hashing (excludes entry_hash itself)."""
    d = asdict(record)
    d.pop("entry_hash", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


# ────────────────────────────────────────────────────────── HMAC key resolution

# Cached after first successful resolution so we don't hit the secret
# backend on every audit write. Cleared by :func:`reset_chain_for_tests`.
_hmac_key_cache: Optional[bytes] = None


def _resolve_hmac_key() -> Optional[bytes]:
    """Return the HMAC key bytes if a reference is configured, else None.

    A None return falls back to plain SHA-256, which is acceptable in dev
    but should be flagged in production by the secret_gate.
    """
    global _hmac_key_cache
    if _hmac_key_cache is not None:
        return _hmac_key_cache
    if not AUDIT_HMAC_KEY_REF:
        return None
    try:
        secret = get_resolver().resolve(AUDIT_HMAC_KEY_REF)
    except SecretResolutionError as exc:
        logger.warning(
            "audit_hmac_key_resolution_failed",
            ref=AUDIT_HMAC_KEY_REF,
            error=str(exc),
        )
        return None
    _hmac_key_cache = secret.encode()
    return _hmac_key_cache


def _compute_hash(canonical_bytes: bytes) -> str:
    key = _resolve_hmac_key()
    if key:
        return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()
    return hashlib.sha256(canonical_bytes).hexdigest()


# ────────────────────────────────────────────────────────── Chain state

_lock = threading.Lock()
_chain_head: str = "0" * 64  # genesis hash
_sequence_counter: int = 0


# ────────────────────────────────────────────────────────── Public API


def log_event(
    event_type: AuditEventType | str,
    outcome: AuditOutcome | str = AuditOutcome.SUCCESS,
    *,
    tenant_id: str = "_global_",
    subject: str = "system",
    source_ip: str = "0.0.0.0",
    resource: str = "",
    detail: Optional[dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
) -> AuditRecord:
    """Write a tamper-evident audit entry. Thread-safe.

    Returns the persisted record so callers can include its correlation_id
    in their structured log line. Audit writes never raise — failures in
    the dispatch backends are logged but never break the calling operation.
    """
    global _sequence_counter, _chain_head

    with _lock:
        _sequence_counter += 1
        record = AuditRecord(
            event_type=str(event_type.value) if isinstance(event_type, Enum) else str(event_type),
            outcome=str(outcome.value) if isinstance(outcome, Enum) else str(outcome),
            tenant_id=tenant_id,
            subject=subject,
            source_ip=source_ip,
            resource=resource,
            detail=detail or {},
            correlation_id=correlation_id or str(uuid.uuid4()),
            sequence=_sequence_counter,
            prev_hash=_chain_head,
        )
        canonical = _canonical(record)
        record.entry_hash = _compute_hash(canonical)
        _chain_head = record.entry_hash

    _dispatch(record)
    return record


def _dispatch(record: AuditRecord) -> None:
    """Fan out to every configured backend. Never raises."""
    for backend in AUDIT_BACKENDS:
        try:
            if backend == "file":
                _write_file(record)
            elif backend == "redis":
                _write_redis(record)
            elif backend == "siem":
                _write_siem(record)
            else:
                logger.warning("audit_unknown_backend", backend=backend)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "audit_dispatch_failed",
                backend=backend,
                event_type=record.event_type,
                error=str(exc),
            )


def _write_file(record: AuditRecord) -> None:
    path = Path(AUDIT_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(asdict(record), separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def _write_redis(record: AuditRecord) -> None:
    """Sync redis write — keeps audit emission synchronous so the entry
    is durable before the calling operation returns. We use a separate
    sync redis client for this path to avoid mixing sync/async."""
    try:
        import redis  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("audit_redis_unavailable_redis_lib_missing")
        return

    from app.core.config import get_settings

    redis_url = get_settings().redis_url
    client = redis.from_url(redis_url, decode_responses=True)
    key = f"audit:{record.tenant_id}:{time.strftime('%Y%m%d', time.gmtime())}"
    client.rpush(key, json.dumps(asdict(record), separators=(",", ":")))
    client.expire(key, AUDIT_REDIS_TTL_DAYS * 86400)


def _write_siem(record: AuditRecord) -> None:
    if not AUDIT_WEBHOOK:
        return
    try:
        import httpx
    except ImportError:  # pragma: no cover — httpx is a hard dep
        return

    payload = json.dumps(asdict(record), separators=(",", ":")).encode()
    key = _resolve_hmac_key() or b"unsigned"
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    try:
        with httpx.Client(timeout=3.0) as client:
            client.post(
                AUDIT_WEBHOOK,
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Platform-Signature": f"sha256={sig}",
                    "X-Platform-Event": record.event_type,
                },
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_siem_post_failed", error=str(exc))


# ────────────────────────────────────────────────────────── Integrity verification


def verify_log_integrity(log_path: Optional[str] = None) -> dict[str, Any]:
    """Walk the JSONL log and verify the hash chain.

    Returns:
        {"ok": bool, "entries": int, "first_violation": int | None, "message": str}

    Run as a nightly cron and alert on ``ok=False``.
    """
    path = Path(log_path or AUDIT_FILE)
    if not path.exists():
        return {
            "ok": True,
            "entries": 0,
            "first_violation": None,
            "message": "no log file yet",
        }

    prev = "0" * 64
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            record = AuditRecord(**data)
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "entries": count,
                "first_violation": count + 1,
                "message": f"parse error at entry {count + 1}: {exc}",
            }

        if record.prev_hash != prev:
            return {
                "ok": False,
                "entries": count,
                "first_violation": count + 1,
                "message": f"chain break at entry {count + 1}",
            }
        canonical = _canonical(record)
        expected = _compute_hash(canonical)
        if record.entry_hash != expected:
            return {
                "ok": False,
                "entries": count,
                "first_violation": count + 1,
                "message": f"hash mismatch at entry {count + 1}",
            }
        prev = record.entry_hash
        count += 1

    return {
        "ok": True,
        "entries": count,
        "first_violation": None,
        "message": f"chain intact — {count} entries verified",
    }


# ────────────────────────────────────────────────────────── Test helpers


def reset_chain_for_tests() -> None:
    """Reset chain state. ONLY for test isolation — never call in app code."""
    global _chain_head, _sequence_counter, _hmac_key_cache
    with _lock:
        _chain_head = "0" * 64
        _sequence_counter = 0
        _hmac_key_cache = None
