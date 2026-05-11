"""Compiled policy snapshots — what stages actually consume.

The DB row is convenient for storage but expensive to use in the hot
path: regex strings would be re-compiled on every request, JSONB lookups
would happen per-rule, etc. ``CompiledPolicy`` is a read-only,
allocation-free representation produced once at policy load time and
shared across requests.

Stage 1 (and the future Stages 2/3) read fields directly from this
object. The pub/sub subscriber rebuilds a CompiledPolicy on every
``policy:invalidation`` message and atomically swaps the cache pointer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from app.policy.types import EnforcementLevel, RuleType, Severity


@dataclass(frozen=True)
class CompiledRule:
    """One rule with its regex (if any) already compiled.

    Pre-compiling the patterns is the difference between sub-1ms Stage 1
    latency and 5+ ms latency on every request. Frozen so a mis-typed
    pattern can never mutate at runtime.
    """

    id: str
    name: str
    type: RuleType
    category: str
    severity: Severity
    action: Literal["block", "flag", "modify", "escalate", "log_only"]
    enabled: bool
    environments: tuple[str, ...] = field(default_factory=tuple)

    # Stage-1 specific — pre-compiled patterns. Only one of these is
    # populated per rule depending on `type`.
    regex_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    keywords: tuple[str, ...] = field(default_factory=tuple)
    threshold: float = 0.0

    # Provider-specific bag (e.g. tool name list for tool_firewall rules).
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CompiledPolicy:
    """Hot-path policy snapshot.

    Created from a Policy row + its embedded rules JSONB. Stages depend
    only on this type, not on SQLAlchemy models — so unit tests can
    construct policies directly without touching the DB.
    """

    policy_id: str
    org_id: str
    version: int
    enforcement_level: EnforcementLevel
    fail_behavior: Literal["open", "closed"]
    ml_confidence_threshold_high: float
    ml_confidence_threshold_low: float

    rules: tuple[CompiledRule, ...] = field(default_factory=tuple)
    tool_allowlist: frozenset[str] = field(default_factory=frozenset)
    tool_denylist: frozenset[str] = field(default_factory=frozenset)
    tool_approval_required: frozenset[str] = field(default_factory=frozenset)
    rate_limits: dict[str, Any] = field(default_factory=dict)
    content_filters: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────── PII patterns


# Default PII regexes injected as Stage 1 rules when content_filters
# requests PII detection. Compiled once at module import.
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    # SSN — 3-2-4 digit groups, allowing dashes or spaces
    "ssn": re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
    # Email — RFC 5321 simplified
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # Credit card — 13–19 digits, allowing spaces / dashes (Luhn checked
    # in Python rather than regex)
    "credit_card": re.compile(r"\b(?:\d[- ]?){12,18}\d\b"),
    # US phone — covers 10-digit and +1-prefixed forms
    "phone_us": re.compile(
        r"\b(?:\+?1[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b"
    ),
    # IPv4
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    ),
    # AWS access key (AKIA followed by 16 chars)
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # OpenAI / Anthropic API keys (sk-... prefix patterns)
    "api_key_sk": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
}


def luhn_check(digits: str) -> bool:
    """RFC-1004 Luhn checksum. Used to suppress false positives on
    credit_card regex (random 13+ digit strings rarely pass Luhn)."""
    s = [int(c) for c in digits if c.isdigit()]
    if len(s) < 13:
        return False
    checksum = 0
    parity = len(s) % 2
    for i, d in enumerate(s):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ─────────────────────────────────────────────── Compilation


def compile_policy(*, policy_row: dict[str, Any]) -> CompiledPolicy:
    """Build a CompiledPolicy from the JSONB-rich row dict.

    ``policy_row`` is the dict shape produced by :class:`Policy.to_response`
    or by hand in tests. We accept dicts (not the SQLAlchemy model) so
    this function can run in any context — pubsub subscribers, tests,
    the runtime agent's policy cache.
    """
    rules: list[CompiledRule] = []
    for r in policy_row.get("rules") or []:
        rules.append(_compile_rule(r))

    return CompiledPolicy(
        policy_id=str(policy_row.get("id", "")),
        org_id=str(policy_row.get("org_id", "")),
        version=int(policy_row.get("version", 1)),
        enforcement_level=policy_row.get("enforcement_level", "fast"),
        fail_behavior=policy_row.get("fail_behavior", "open"),
        ml_confidence_threshold_high=float(
            policy_row.get("ml_confidence_threshold_high", 0.7)
        ),
        ml_confidence_threshold_low=float(
            policy_row.get("ml_confidence_threshold_low", 0.3)
        ),
        rules=tuple(rules),
        tool_allowlist=frozenset(policy_row.get("tool_allowlist") or []),
        tool_denylist=frozenset(policy_row.get("tool_denylist") or []),
        tool_approval_required=frozenset(
            policy_row.get("tool_approval_required") or []
        ),
        rate_limits=dict(policy_row.get("rate_limits") or {}),
        content_filters=dict(policy_row.get("content_filters") or {}),
    )


def _compile_rule(r: dict[str, Any]) -> CompiledRule:
    config = dict(r.get("config") or {})

    regex_patterns: tuple[re.Pattern[str], ...] = ()
    keywords: tuple[str, ...] = ()

    rule_type = r.get("type", "regex")
    if rule_type == "regex":
        patterns = config.get("patterns") or []
        regex_patterns = tuple(re.compile(p, re.IGNORECASE) for p in patterns)
    elif rule_type == "keyword":
        keywords = tuple(str(k).lower() for k in config.get("keywords") or [])
    elif rule_type == "pii_pattern":
        # PII pattern rules either use the canonical PII_PATTERNS table
        # (config.types: ["ssn", "email", ...]) OR provide custom patterns
        types = config.get("types") or []
        chosen: list[re.Pattern[str]] = []
        for t in types:
            if t in PII_PATTERNS:
                chosen.append(PII_PATTERNS[t])
        regex_patterns = tuple(chosen)

    return CompiledRule(
        id=str(r.get("id", "")),
        name=r.get("name", ""),
        type=rule_type,
        category=r.get("category", ""),
        severity=r.get("severity", "medium"),
        action=r.get("action", "flag"),
        enabled=bool(r.get("enabled", True)),
        environments=tuple(r.get("environments") or []),
        regex_patterns=regex_patterns,
        keywords=keywords,
        threshold=float(config.get("threshold", 0.0)),
        config=config,
    )
