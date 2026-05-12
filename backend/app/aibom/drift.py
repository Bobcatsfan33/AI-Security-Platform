"""Drift detection — compare asset configurations across snapshots.

When an asset's config changes after a prior evaluation, we record the
delta as a "drift event." Severity is determined by which fields
changed:

  - system_prompt change            → high      (intent shift)
  - model_name / model_version      → high      (security characteristics
                                                  can change between models)
  - tools added / removed           → medium    (surface change)
  - mcp_servers added / removed     → medium
  - rag_sources changed             → medium    (data lineage change)
  - exposure / data_classification  → high      (compliance impact)
  - temperature / max_tokens / etc. → low

This is the platform's "did the asset's risk posture change" signal.
The runtime agent doesn't act on drift directly; the dashboard alerts
operators, who can choose to trigger a re-evaluation.

Origin: distilled from TokenDNA modules/identity/attestation_drift.py
+ permission_drift.py logic. Their schemas are different (they track
agent permission scope changes against an attested baseline); ours
tracks asset configuration drift against the previous evaluation
snapshot. Same intent, simpler shape.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]


# Field-level severity classification. Fields not in this map default
# to "low".
FIELD_SEVERITY: dict[str, Severity] = {
    "system_prompt": "high",
    "model_name": "high",
    "model_version": "medium",
    "provider": "high",
    "tools": "medium",
    "mcp_servers": "medium",
    "rag_sources": "medium",
    "plugins": "medium",
    "fine_tuning": "high",
    "exposure": "high",
    "data_classification": "high",
    "is_agentic": "high",
    "allowed_external_actions": "medium",
    "regulatory_scope": "medium",
    "temperature": "low",
    "max_tokens": "low",
    "top_p": "low",
    "max_tool_calls_per_session": "low",
    "human_in_loop_required": "high",
}


@dataclass(frozen=True)
class FieldChange:
    field: str
    severity: Severity
    old_fingerprint: str | None
    new_fingerprint: str | None
    detail: str = ""


@dataclass(frozen=True)
class DriftReport:
    asset_id: str
    changed: bool
    changes: tuple[FieldChange, ...]
    max_severity: Severity
    summary: str

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


_TRACKED_FIELDS: tuple[str, ...] = tuple(FIELD_SEVERITY.keys())

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def compute_drift(
    *, current: dict[str, Any], baseline: dict[str, Any] | None
) -> DriftReport:
    """Compare two asset config dicts and return a structured drift report.

    ``baseline`` is the snapshot we're comparing against (typically the
    asset's config at the time of the last successful evaluation). If
    ``baseline`` is None, every tracked field counts as "newly present"
    — useful for surfacing how much has changed since the asset was
    first registered.
    """
    asset_id = str(current.get("id") or "")
    changes: list[FieldChange] = []

    for field_name in _TRACKED_FIELDS:
        old_val = baseline.get(field_name) if baseline is not None else None
        new_val = current.get(field_name)

        old_fp = _fingerprint(old_val)
        new_fp = _fingerprint(new_val)

        if old_fp == new_fp:
            continue

        sev = FIELD_SEVERITY.get(field_name, "low")
        detail = _describe_change(field_name, old_val, new_val)
        changes.append(
            FieldChange(
                field=field_name,
                severity=sev,
                old_fingerprint=old_fp,
                new_fingerprint=new_fp,
                detail=detail,
            )
        )

    if not changes:
        return DriftReport(
            asset_id=asset_id,
            changed=False,
            changes=(),
            max_severity="info",
            summary="no drift detected",
        )

    max_sev = max(changes, key=lambda c: _SEVERITY_RANK[c.severity]).severity
    summary = _summary(changes, max_sev)

    return DriftReport(
        asset_id=asset_id,
        changed=True,
        changes=tuple(changes),
        max_severity=max_sev,
        summary=summary,
    )


def _fingerprint(value: Any) -> str | None:
    """SHA-256 over a deterministic representation. None passes through
    so first-time-set fields show as old_fp=None / new_fp=hash."""
    if value is None:
        return None
    if isinstance(value, str):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    if isinstance(value, (bool, int, float)):
        return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()[:16]
    if isinstance(value, (list, tuple, dict)):
        import json

        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _describe_change(field_name: str, old: Any, new: Any) -> str:
    """Render a short human-readable change description.

    The full values are NEVER included in detail strings — those would
    leak sensitive system_prompt text or RAG contents into the drift
    log. Detail strings carry counts, sizes, and presence flags only.
    """
    if old is None and new is not None:
        return f"{field_name} added"
    if old is not None and new is None:
        return f"{field_name} removed"
    if isinstance(old, list) and isinstance(new, list):
        added = len(new) - len(old)
        if added > 0:
            return f"{field_name}: +{added} item(s)"
        if added < 0:
            return f"{field_name}: {added} item(s) removed"
        return f"{field_name}: contents changed (count unchanged)"
    if isinstance(old, str) and isinstance(new, str):
        return (
            f"{field_name}: changed "
            f"({len(old)}→{len(new)} chars)"
        )
    return f"{field_name}: modified"


def _summary(changes: list[FieldChange], max_severity: Severity) -> str:
    high_count = sum(1 for c in changes if c.severity in ("high", "critical"))
    total = len(changes)
    return (
        f"{total} field(s) drifted, {high_count} at high+ severity "
        f"(max={max_severity})"
    )
