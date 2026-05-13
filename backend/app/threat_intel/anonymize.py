"""Anonymization utilities for cross-org threat sharing.

The threat intelligence engine aggregates attack data across customer
orgs. Before any data leaves its origin tenant, it is run through
these utilities so the resulting cluster / pattern cannot be traced
back to a specific customer, user, or workload.

Rules:
- Org and user IDs are HMAC-hashed with a per-deployment salt so
  identical IDs across the same deployment hash identically (enables
  joining across time) but cannot be inverted.
- Free-text fields (prompts, response snippets) are k-anonymized:
  any token appearing in fewer than k=5 distinct orgs is dropped.
- Numeric fields are bucketed (timestamps to the nearest hour, costs
  to the nearest 10c, latencies to 100ms).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime, timezone

# Hash salt — supplied by env. If absent, we use a fixed placeholder so
# tests run, but the secret_gate flags this in production.
_HMAC_SALT = os.getenv("THREAT_INTEL_HMAC_SALT", "")


def _key() -> bytes:
    return (_HMAC_SALT or "dev-only-salt-do-not-use-in-prod").encode("utf-8")


def hash_id(value: str) -> str:
    """Deterministic HMAC-SHA256 hex digest. Suitable for joining the
    same logical entity across multiple anonymized records, never
    reversible to the original ID."""
    return hmac.new(_key(), value.encode("utf-8"), hashlib.sha256).hexdigest()


# ─────────────────────────────────────────── text normalisation


_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_RE = re.compile(r"https?://\S+")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_LONG_DIGIT_RE = re.compile(r"\b\d{6,}\b")
_BEARER_RE = re.compile(r"\b(?:Bearer|api[_-]?key|token)\s*[:=]?\s*\S+", re.I)


def redact_text(text: str) -> str:
    """Replace common PII patterns with literal tokens. Order matters —
    e.g. bearer tokens contain URLs."""
    if not text:
        return ""
    text = _BEARER_RE.sub("[REDACTED_TOKEN]", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _URL_RE.sub("[REDACTED_URL]", text)
    text = _IPV4_RE.sub("[REDACTED_IP]", text)
    text = _UUID_RE.sub("[REDACTED_UUID]", text)
    text = _LONG_DIGIT_RE.sub("[REDACTED_NUMBER]", text)
    return text


# ─────────────────────────────────────────── numeric bucketing


def bucket_timestamp(ts: datetime) -> datetime:
    """Round to the nearest hour (UTC). Hides exact timing while
    preserving daily/hourly patterns."""
    ts = ts.astimezone(timezone.utc)
    return ts.replace(minute=0, second=0, microsecond=0)


def bucket_cost(cost_usd: float) -> float:
    """Round to the nearest 10 cents."""
    return round(cost_usd / 0.10) * 0.10


def bucket_latency_ms(latency_ms: int) -> int:
    """Round to the nearest 100ms."""
    return round(latency_ms / 100) * 100
