"""MCP Intent-Aware Inspection.

OAuth says *who* called a tool. This inspector says *whether the call is
what it claims to be, whether the agent is allowed to make it, and what
the chain of recent calls looks like for known attack patterns*.

Origin: ported from TokenDNA ``modules/identity/mcp_inspector.py``
(1140 lines). The platform port focuses on the deterministic core:

  - Tool intent profiles + per-call inspection (params allow/forbid
    lists, value constraints, value substring scanning for SQL/shell-
    injection-style payloads)
  - Bounded-gap subsequence matcher for known attack chains
    (read_then_exfil, privilege_ladder, scope_creep, data_staging,
    lateral_move, admin_takeover)
  - Risk scoring + recommendation (allow / flag / block)

Deferred to a follow-on chunk:
  - FastAPI routes (/v1/mcp/inspect, /tools, /violations, /chain/{sid})
  - Persistence layer (in-memory call-chain store for now)
  - trust_graph + intent_correlation forwarding (depends on those
    Sprint 8 modules being ported first)
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from app.core.coerce import as_bool, as_number, as_positive_int

# ─────────────────────────────────────────────── Tunables

DRIFT_BLOCK_THRESHOLD: float = float(os.getenv("MCP_DRIFT_BLOCK_THRESHOLD", "0.8"))
DRIFT_FLAG_THRESHOLD: float = float(os.getenv("MCP_DRIFT_FLAG_THRESHOLD", "0.5"))

# Bounded gap for chain pattern matching — see _find_subsequence_with_gap.
# Suffix-only matching (gap=0) is too brittle; a sophisticated attacker
# injects benign calls between real steps. Bounding the gap balances
# coverage and FP rate.
CHAIN_PATTERN_MAX_GAP: int = int(os.getenv("MCP_CHAIN_MAX_GAP", "3"))


AccessMode = Literal["read", "write", "execute", "admin", "exfil"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Recommendation = Literal["allow", "flag", "block"]


# ─────────────────────────────────────────────── Schemas


@dataclass(frozen=True)
class ToolProfile:
    """Declared intent for a single MCP tool.

    Operators register tool profiles via the admin API (Sprint 6
    follow-on). Built-in profiles for common tools ship in
    DEFAULT_TOOL_PROFILES so a fresh deployment has sensible defaults
    on day one.
    """

    tool_name: str
    access_mode: AccessMode
    description: str = ""
    allowed_params: tuple[str, ...] = field(default_factory=tuple)
    forbidden_params: tuple[str, ...] = field(default_factory=tuple)
    param_constraints: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Non-empty ONLY for a profile loaded from storage whose JSONB was
    # malformed — each entry names one field the operator's intent could not be
    # read from. Built-in profiles are literals and always leave this empty. The
    # inspector turns a non-empty value into a ``malformed_profile`` violation
    # (deny-by-default), so unreadable config cannot silently reduce scrutiny.
    integrity_issues: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Violation:
    type: str
    detail: str
    severity: Severity


@dataclass(frozen=True)
class ChainMatch:
    """A known attack pattern found in recent calls."""

    name: str
    description: str
    sequence: tuple[AccessMode, ...]
    severity: Severity
    mitre_technique: str
    positions: tuple[int, ...]
    gap: int
    confidence: float


@dataclass(frozen=True)
class InspectionResult:
    """The per-call verdict. Callers (the runtime agent, the SDK
    wrappers) act on ``recommendation`` and persist the rest for the
    investigation surface (Sprint 8)."""

    tool_name: str
    access_mode: AccessMode | None
    allowed: bool
    risk_score: float
    recommendation: Recommendation
    violations: tuple[Violation, ...]
    chain_matches: tuple[ChainMatch, ...]


# ─────────────────────────────────────────────── Known attack chains


_CHAIN_PATTERNS: tuple[dict[str, Any], ...] = (
    {
        "name": "read_then_exfil",
        "description": "Read followed by exfiltration",
        "sequence": ("read", "exfil"),
        "severity": "critical",
        "mitre_technique": "T1048",
    },
    {
        "name": "privilege_ladder",
        "description": "Progressive escalation: read → write → execute",
        "sequence": ("read", "write", "execute"),
        "severity": "high",
        "mitre_technique": "T1078",
    },
    {
        "name": "scope_creep",
        "description": "Agent expands its own policy scope before acting",
        "sequence": ("admin", "write", "execute"),
        "severity": "critical",
        "mitre_technique": "T1548",
    },
    {
        "name": "data_staging",
        "description": "Bulk read followed by write (staging for exfil)",
        "sequence": ("read", "read", "write"),
        "severity": "high",
        "mitre_technique": "T1074",
    },
    {
        "name": "lateral_move",
        "description": "Connect, enumerate, connect new host",
        "sequence": ("execute", "read", "execute"),
        "severity": "high",
        "mitre_technique": "T1021",
    },
    {
        "name": "admin_takeover",
        "description": "Admin action immediately followed by exfil",
        "sequence": ("admin", "exfil"),
        "severity": "critical",
        "mitre_technique": "T1136",
    },
)


# ─────────────────────────────────────────────── Built-in tool profiles


DEFAULT_TOOL_PROFILES: tuple[ToolProfile, ...] = (
    ToolProfile(
        tool_name="read_file",
        access_mode="read",
        description="Read a file by path",
        allowed_params=("path", "encoding", "lines", "offset"),
        forbidden_params=("write", "delete", "execute", "command", "shell"),
        param_constraints={"path": {"type": "string", "max_length": 4096}},
    ),
    ToolProfile(
        tool_name="write_file",
        access_mode="write",
        description="Write or create a file",
        allowed_params=("path", "content", "mode", "encoding"),
        forbidden_params=("execute", "command", "shell", "rm", "delete"),
        param_constraints={"path": {"type": "string", "max_length": 4096}},
    ),
    ToolProfile(
        tool_name="execute_command",
        access_mode="execute",
        description="Execute a shell command",
        allowed_params=("command", "args", "cwd", "timeout"),
        param_constraints={"timeout": {"type": "number", "max": 300}},
    ),
    ToolProfile(
        tool_name="send_email",
        access_mode="exfil",
        description="Send an email (exfil vector)",
        allowed_params=("to", "subject", "body", "from"),
        forbidden_params=("attachment_path", "bcc_all"),
    ),
    ToolProfile(
        tool_name="http_request",
        access_mode="exfil",
        description="Outbound HTTP request",
        allowed_params=("url", "method", "headers", "body", "timeout"),
        param_constraints={
            "method": {
                "type": "enum",
                "values": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            }
        },
    ),
    ToolProfile(
        tool_name="database_query",
        access_mode="read",
        description="Read-only database query",
        allowed_params=("query", "params", "database", "timeout"),
        forbidden_params=("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"),
    ),
    ToolProfile(
        tool_name="database_write",
        access_mode="write",
        description="Database write",
        allowed_params=("query", "params", "database", "timeout"),
        forbidden_params=("DROP", "ALTER", "TRUNCATE"),
    ),
    ToolProfile(
        tool_name="update_policy",
        access_mode="admin",
        description="Update an agent policy rule",
        allowed_params=("policy_id", "rules", "actor", "reason"),
        forbidden_params=("agent_id_self", "override_all"),
    ),
)


# ─────────────────────────────────────────────── Param inspection


def _sanitize_str_list(raw: Any, field_name: str, issues: list[str]) -> tuple[str, ...]:
    """A tuple of the string items of a stored JSONB list. A non-list value, or
    a list with non-string entries, records an integrity issue rather than
    fabricating (``tuple("shell")`` would count five params)."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        issues.append(f"{field_name} is not a list")
        return ()
    clean = tuple(x for x in raw if isinstance(x, str))
    if len(clean) != len(raw):
        issues.append(f"{field_name} contains non-string entries")
    return clean


def _sanitize_rule(name: str, raw_rule: Any, issues: list[str]) -> dict[str, Any] | None:
    """Coerce one param-constraint rule read from storage. Only correctly-typed
    fields survive; a present-but-unparseable field is dropped AND recorded as
    an integrity issue (so it flags, not silently no-ops). Returns None when the
    rule is not an object at all — the whole rule is unreadable."""
    if not isinstance(raw_rule, dict):
        issues.append(f"constraint {name!r} is not an object")
        return None
    clean: dict[str, Any] = {}
    if "required" in raw_rule:
        b = as_bool(raw_rule["required"])
        if b is None:
            issues.append(f"constraint {name!r}.required is not a boolean")
        else:
            clean["required"] = b
    if "type" in raw_rule:
        kind = raw_rule["type"]
        if isinstance(kind, str):
            clean["type"] = kind
        else:
            issues.append(f"constraint {name!r}.type is not a string")
    if "max_length" in raw_rule:
        v = as_positive_int(raw_rule["max_length"])
        if v is None:
            issues.append(f"constraint {name!r}.max_length is not a positive integer")
        else:
            clean["max_length"] = v
    if "max" in raw_rule:
        v = as_number(raw_rule["max"])
        if v is None:
            issues.append(f"constraint {name!r}.max is not a number")
        else:
            clean["max"] = v
    if "pattern" in raw_rule:
        pat = raw_rule["pattern"]
        if not isinstance(pat, str):
            issues.append(f"constraint {name!r}.pattern is not a string")
        else:
            try:
                re.compile(pat)
                clean["pattern"] = pat
            except re.error:
                issues.append(f"constraint {name!r}.pattern is not a valid regex")
    if "values" in raw_rule:
        vals = raw_rule["values"]
        if isinstance(vals, list):
            clean["values"] = vals
        else:
            issues.append(f"constraint {name!r}.values is not a list")
    return clean


def sanitize_stored_profile(
    *,
    tool_name: str,
    access_mode: AccessMode,
    description: str,
    allowed_params: Any,
    forbidden_params: Any,
    param_constraints: Any,
) -> ToolProfile:
    """Build a :class:`ToolProfile` from raw stored JSONB, tolerating any shape.

    A stored profile is operator-shaped: a connector, a migration, or a
    hand-edit can write a string where a list was meant, or a scalar where a
    constraint object was meant. Reading it as if it were typed either
    fabricates (``tuple("shell")`` is five params) or 500s (``rule.get`` on a
    non-dict — the GAP-019 crash). This coerces every field strictly: anything
    unparseable is dropped from enforcement AND named in ``integrity_issues``,
    so the inspect path neither crashes nor silently trusts a corrupt profile.
    """
    issues: list[str] = []
    allowed = _sanitize_str_list(allowed_params, "allowed_params", issues)
    forbidden = _sanitize_str_list(forbidden_params, "forbidden_params", issues)

    constraints: dict[str, dict[str, Any]] = {}
    if isinstance(param_constraints, dict):
        for key, raw_rule in param_constraints.items():
            clean = _sanitize_rule(str(key), raw_rule, issues)
            if clean is not None:
                constraints[str(key)] = clean
    elif param_constraints is not None:
        issues.append("param_constraints is not an object")

    return ToolProfile(
        tool_name=tool_name,
        access_mode=access_mode,
        description=description if isinstance(description, str) else "",
        allowed_params=allowed,
        forbidden_params=forbidden,
        param_constraints=constraints,
        integrity_issues=tuple(issues),
    )


def _inspect_params(params: dict[str, Any], profile: ToolProfile) -> list[Violation]:
    """Check params against the tool's intent profile. Empty list = clean."""
    violations: list[Violation] = []
    forbidden = set(profile.forbidden_params)
    constraints = profile.param_constraints or {}

    # 1. Forbidden parameter KEYS
    for key in params:
        if key in forbidden:
            violations.append(
                Violation(
                    type="forbidden_param",
                    detail=(f"Parameter {key!r} is forbidden for tool {profile.tool_name!r}"),
                    severity="high",
                )
            )

    # 2. Forbidden parameter VALUES — substring case-insensitive scan.
    #    Catches query="SELECT * FROM x; DROP TABLE y" against
    #    forbidden_params=["DROP"] which is the SQL-injection pattern.
    for fkey in forbidden:
        for pkey, pval in params.items():
            if isinstance(pval, str) and fkey.upper() in pval.upper():
                violations.append(
                    Violation(
                        type="forbidden_value",
                        detail=(
                            f"Parameter {pkey!r} contains forbidden token "
                            f"{fkey!r} in tool {profile.tool_name!r}"
                        ),
                        severity="high",
                    )
                )

    # 3. Declared constraints
    for param_name, rule in constraints.items():
        val = params.get(param_name)
        if rule.get("required") and val is None:
            violations.append(
                Violation(
                    type="missing_required_param",
                    detail=f"Required parameter {param_name!r} is missing",
                    severity="medium",
                )
            )
            continue
        if val is None:
            continue
        kind = rule.get("type")
        if kind == "string":
            max_len = rule.get("max_length")
            if max_len and isinstance(val, str) and len(val) > max_len:
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(f"Parameter {param_name!r} exceeds max_length {max_len}"),
                        severity="low",
                    )
                )
            pattern = rule.get("pattern")
            if pattern and isinstance(val, str) and not re.search(pattern, val):
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(f"Parameter {param_name!r} does not match pattern"),
                        severity="low",
                    )
                )
        elif kind == "number":
            max_val = rule.get("max")
            if max_val is not None and isinstance(val, (int, float)) and val > max_val:
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(f"Parameter {param_name!r} value {val} exceeds max {max_val}"),
                        severity="medium",
                    )
                )
        elif kind == "enum":
            # A list, not a set: stored ``values`` may contain unhashable items
            # (a nested object), and ``set()`` of those would TypeError — the
            # very 500 class this module is hardening against. Membership on a
            # list needs no hashing and no ordering.
            allowed_vals = rule.get("values", [])
            if val not in allowed_vals:
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(
                            f"Parameter {param_name!r} value {val!r} not in "
                            f"allowed values {allowed_vals}"
                        ),
                        severity="medium",
                    )
                )

    return violations


# ─────────────────────────────────────────────── Chain pattern matcher


def _find_subsequence_with_gap(
    haystack: Sequence[str],
    needle: Sequence[str],
    *,
    max_gap: int,
) -> tuple[bool, int, list[int]]:
    """Find ``needle`` as a non-contiguous subsequence in ``haystack`` with
    at most ``max_gap`` unrelated entries between consecutive needle
    elements, AND the LAST element of needle must equal the LAST element
    of haystack (so the pattern is "happening now" rather than buried
    in history).

    Returns ``(matched, total_gap, positions)``.
    """
    if not needle or not haystack:
        return False, 0, []
    if haystack[-1] != needle[-1]:
        return False, 0, []

    positions: list[int] = [len(haystack) - 1]
    needle_idx = len(needle) - 2
    haystack_idx = len(haystack) - 2
    last_match_pos = len(haystack) - 1

    while needle_idx >= 0 and haystack_idx >= 0:
        gap = (last_match_pos - haystack_idx) - 1
        if gap > max_gap:
            return False, 0, []
        if haystack[haystack_idx] == needle[needle_idx]:
            positions.insert(0, haystack_idx)
            last_match_pos = haystack_idx
            needle_idx -= 1
        haystack_idx -= 1

    if needle_idx >= 0:
        return False, 0, []

    total_gap = sum(positions[i + 1] - positions[i] - 1 for i in range(len(positions) - 1))
    return True, total_gap, positions


def match_chain_patterns(
    recent_modes: Sequence[AccessMode],
    *,
    max_gap: int = CHAIN_PATTERN_MAX_GAP,
) -> list[ChainMatch]:
    """Scan the recent-access-mode sequence for any known attack chain.

    The last entry in ``recent_modes`` MUST equal the final step of a
    pattern for it to match. Earlier steps may have up to ``max_gap``
    unrelated calls between them. Confidence falls off as gap grows.
    """
    out: list[ChainMatch] = []
    for pattern in _CHAIN_PATTERNS:
        seq = pattern["sequence"]
        ok, total_gap, positions = _find_subsequence_with_gap(
            list(recent_modes), list(seq), max_gap=max_gap
        )
        if not ok:
            continue
        max_possible_gap = max(1, (len(seq) - 1) * max_gap)
        confidence = round(1.0 - (total_gap / max_possible_gap) * 0.5, 3)
        out.append(
            ChainMatch(
                name=pattern["name"],
                description=pattern["description"],
                sequence=seq,
                severity=pattern["severity"],
                mitre_technique=pattern["mitre_technique"],
                positions=tuple(positions),
                gap=total_gap,
                confidence=confidence,
            )
        )
    return out


# ─────────────────────────────────────────────── Risk + recommendation


_SEVERITY_RISK = {"critical": 0.9, "high": 0.6, "medium": 0.35, "low": 0.15, "info": 0.05}
_CHAIN_RISK = {"critical": 0.6, "high": 0.35, "medium": 0.15, "low": 0.05, "info": 0.0}


def compute_risk_score(
    violations: Sequence[Violation], chain_matches: Sequence[ChainMatch]
) -> float:
    """Combine violation severity + chain matches into a 0-1 risk score.

    Base score is the highest single-violation severity. Chain matches
    add on top, capped at 1.0.
    """
    if not violations and not chain_matches:
        return 0.0
    base = max((_SEVERITY_RISK.get(v.severity, 0.15) for v in violations), default=0.0)
    chain_bonus = max((_CHAIN_RISK.get(c.severity, 0.1) for c in chain_matches), default=0.0)
    return min(1.0, base + chain_bonus)


def recommendation(risk_score: float) -> Recommendation:
    if risk_score >= DRIFT_BLOCK_THRESHOLD:
        return "block"
    if risk_score >= DRIFT_FLAG_THRESHOLD:
        return "flag"
    return "allow"


# Violation types that deny STRUCTURALLY — the recommendation cannot be "allow"
# when one is present, regardless of the (env-tunable) risk thresholds. A
# malformed profile currently denies only because severity high (0.6) clears the
# default flag threshold (0.5); an operator who raises MCP_DRIFT_FLAG_THRESHOLD
# to 0.7 would otherwise silently convert every malformed profile to allow —
# fail-open on the enforcement path via a config knob nobody decided to flip.
# The deny is a property of the violation SET, not of a threshold. Same instinct
# as a zero-value that is non-permissive by construction.
_DENY_FLOOR_TYPES: frozenset[str] = frozenset({"malformed_profile"})


# ─────────────────────────────────────────────── Top-level inspection


def inspect_call(
    *,
    tool_name: str,
    params: dict[str, Any],
    profile: ToolProfile | None,
    recent_modes: Sequence[AccessMode] | None = None,
) -> InspectionResult:
    """Inspect one tool call. Pure function — no I/O, no DB.

    ``profile`` is None when the tool isn't registered. We treat that
    as a violation (unknown tools default to fail-closed semantics in
    callers that want strict tool firewalling) but compute a moderate
    risk score so callers can flag rather than block by default.

    ``recent_modes`` should include THIS call's access_mode as the last
    element if the caller wants chain detection that includes the
    current call. Pass None or [] to skip chain analysis (e.g. first
    call in a session).
    """
    violations: list[Violation] = []

    if profile is None:
        violations.append(
            Violation(
                type="unregistered_tool",
                detail=f"Tool {tool_name!r} has no registered intent profile",
                severity="medium",
            )
        )
        access_mode: AccessMode | None = None
    else:
        access_mode = profile.access_mode
        # A stored profile that could not be fully parsed must not inspect as
        # "no constraints" — on the enforcement path that is fail-open. Flag it
        # (deny-by-default) and name why, so the operator fixes the profile
        # rather than the corruption silently widening what the agent may do.
        if profile.integrity_issues:
            violations.append(
                Violation(
                    type="malformed_profile",
                    detail=(
                        "stored tool profile is malformed and cannot be fully "
                        f"enforced ({'; '.join(profile.integrity_issues)}) — "
                        "flagged rather than trusted"
                    ),
                    severity="high",
                )
            )
        violations.extend(_inspect_params(params, profile))

    chain_matches: list[ChainMatch] = []
    if recent_modes:
        chain_matches = match_chain_patterns(list(recent_modes))

    risk = compute_risk_score(violations, chain_matches)
    rec = recommendation(risk)
    # Structural deny floor: a threshold change must not be able to turn a
    # deny-by-default violation into "allow". If one is present and the score
    # landed below the flag threshold, floor the recommendation to "flag".
    if rec == "allow" and any(v.type in _DENY_FLOOR_TYPES for v in violations):
        rec = "flag"

    return InspectionResult(
        tool_name=tool_name,
        access_mode=access_mode,
        allowed=(rec == "allow"),
        risk_score=risk,
        recommendation=rec,
        violations=tuple(violations),
        chain_matches=tuple(chain_matches),
    )


# ─────────────────────────────────────────────── Registry helpers


def builtin_profiles_by_name() -> dict[str, ToolProfile]:
    """Convenience: indexed view of DEFAULT_TOOL_PROFILES. Callers can
    extend this dict with custom profiles loaded from the DB."""
    return {p.tool_name: p for p in DEFAULT_TOOL_PROFILES}
