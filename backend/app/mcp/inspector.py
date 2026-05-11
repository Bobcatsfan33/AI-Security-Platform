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


def _inspect_params(
    params: dict[str, Any], profile: ToolProfile
) -> list[Violation]:
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
                    detail=(
                        f"Parameter {key!r} is forbidden for tool "
                        f"{profile.tool_name!r}"
                    ),
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
                        detail=(
                            f"Parameter {param_name!r} exceeds max_length {max_len}"
                        ),
                        severity="low",
                    )
                )
            pattern = rule.get("pattern")
            if pattern and isinstance(val, str) and not re.search(pattern, val):
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(
                            f"Parameter {param_name!r} does not match pattern"
                        ),
                        severity="low",
                    )
                )
        elif kind == "number":
            max_val = rule.get("max")
            if (
                max_val is not None
                and isinstance(val, (int, float))
                and val > max_val
            ):
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(
                            f"Parameter {param_name!r} value {val} exceeds "
                            f"max {max_val}"
                        ),
                        severity="medium",
                    )
                )
        elif kind == "enum":
            allowed_vals = set(rule.get("values", []))
            if val not in allowed_vals:
                violations.append(
                    Violation(
                        type="param_constraint_violation",
                        detail=(
                            f"Parameter {param_name!r} value {val!r} not in "
                            f"allowed values {sorted(allowed_vals)}"
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

    total_gap = sum(
        positions[i + 1] - positions[i] - 1 for i in range(len(positions) - 1)
    )
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
    """Combine violation severity + chain matches into a 0–1 risk score.

    Base score is the highest single-violation severity. Chain matches
    add on top, capped at 1.0.
    """
    if not violations and not chain_matches:
        return 0.0
    base = max(
        (_SEVERITY_RISK.get(v.severity, 0.15) for v in violations), default=0.0
    )
    chain_bonus = max(
        (_CHAIN_RISK.get(c.severity, 0.1) for c in chain_matches), default=0.0
    )
    return min(1.0, base + chain_bonus)


def recommendation(risk_score: float) -> Recommendation:
    if risk_score >= DRIFT_BLOCK_THRESHOLD:
        return "block"
    if risk_score >= DRIFT_FLAG_THRESHOLD:
        return "flag"
    return "allow"


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
        violations.extend(_inspect_params(params, profile))

    chain_matches: list[ChainMatch] = []
    if recent_modes:
        chain_matches = match_chain_patterns(list(recent_modes))

    risk = compute_risk_score(violations, chain_matches)
    rec = recommendation(risk)

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
