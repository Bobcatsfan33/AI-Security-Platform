"""Compliance evidence-pack exporter.

Auditors don't want narrative — they want artefacts. This module
assembles a ZIP containing:

  manifest.json           index of files + hashes
  controls/<framework>.json   per-control implementation evidence
  findings.jsonl          every finding (open + closed) for the period
  audit_log.jsonl         hash-chained audit records for the period
  evaluations.csv         evaluation runs + summary stats
  policies.json           policy snapshots active in the period

Supported frameworks: SOC 2 Type II, ISO 27001, FedRAMP Moderate. The
mapping from platform features to control IDs lives in
``CONTROL_MAPPINGS`` below.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.evaluation import Evaluation
from app.db.models.finding import Finding
from app.db.models.policy import Policy

logger = logging.getLogger("platform.compliance")

Framework = Literal["soc2", "iso27001", "fedramp_moderate"]


# Map framework → control_id → evidence pointer.
# Each entry is the platform's claimed implementation of one control.
CONTROL_MAPPINGS: dict[Framework, dict[str, dict[str, str]]] = {
    "soc2": {
        "CC6.1": {
            "title": "Logical access controls",
            "evidence": (
                "audit_log.jsonl, policies.json — RBAC enforced at the "
                "auth dependency layer; every privileged operation emits "
                "an audit record."
            ),
        },
        "CC6.6": {
            "title": "Encryption in transit",
            "evidence": (
                "TLS terminated at ingress; field-level encryption "
                "(versioned Fernet) for secrets at rest; see "
                "policies.json for the active key version."
            ),
        },
        "CC7.2": {
            "title": "System monitoring",
            "evidence": (
                "ClickHouse runtime_events table, SIEM forwarders, and "
                "dashboard queries provide continuous monitoring. See "
                "findings.jsonl for the open findings catalog."
            ),
        },
        "CC7.3": {
            "title": "Anomaly detection",
            "evidence": (
                "Statistical detector at /v1/anomalies (volume spike, "
                "novel transitions, risk inflation) — see evaluations.csv."
            ),
        },
    },
    "iso27001": {
        "A.5.10": {
            "title": "Acceptable use of information",
            "evidence": (
                "Policy snapshots define acceptable AI use (Stage 1 regex, "
                "Stage 2 ML, Stage 3 LLM judge); see policies.json."
            ),
        },
        "A.5.23": {
            "title": "Use of cloud services",
            "evidence": (
                "Connector configs (encrypted at rest) bind models to "
                "authorised cloud providers."
            ),
        },
        "A.8.16": {
            "title": "Monitoring activities",
            "evidence": (
                "audit_log.jsonl is hash-chained per NIST 800-53 AU-9; "
                "tamper-evident."
            ),
        },
    },
    "fedramp_moderate": {
        "AU-2": {
            "title": "Event Logging",
            "evidence": "See audit_log.jsonl — hash-chained, AU-3 fields complete.",
        },
        "AU-9": {
            "title": "Protection of Audit Information",
            "evidence": (
                "HMAC-SHA256 chain; integrity verified nightly via "
                "verify_log_integrity()."
            ),
        },
        "RA-5": {
            "title": "Vulnerability Scanning",
            "evidence": (
                "evaluations.csv lists scheduled scans against every "
                "AI asset; findings.jsonl provides outputs."
            ),
        },
        "SI-4": {
            "title": "System Monitoring",
            "evidence": (
                "Runtime agent emits telemetry to /v1/runtime/events; "
                "anomaly detector flags deviations."
            ),
        },
    },
}


@dataclass(frozen=True)
class EvidencePackInputs:
    org_id: uuid.UUID
    framework: Framework
    period_start: datetime
    period_end: datetime
    audit_log_jsonl: str = ""   # caller-supplied; this module doesn't tail the file


async def build_pack(
    db: AsyncSession,
    inputs: EvidencePackInputs,
) -> bytes:
    """Assemble the evidence pack as a ZIP. Returns the binary bytes
    ready to stream to the caller. Pure-async — no temp files."""
    findings = await _load_findings(db, inputs)
    evaluations = await _load_evaluations(db, inputs)
    policies = await _load_policies(db, inputs.org_id)

    controls = CONTROL_MAPPINGS.get(inputs.framework, {})
    if not controls:
        raise ValueError(f"unsupported framework: {inputs.framework}")

    files: dict[str, bytes] = {}
    files[f"controls/{inputs.framework}.json"] = json.dumps(
        controls, indent=2
    ).encode("utf-8")
    files["findings.jsonl"] = _to_jsonl(_finding_dicts(findings))
    files["evaluations.csv"] = _to_csv(
        ["id", "asset_id", "started_at", "completed_at", "status", "score",
         "findings_count", "critical_findings"],
        _evaluation_rows(evaluations),
    )
    files["policies.json"] = json.dumps(_policy_dicts(policies), indent=2).encode()
    files["audit_log.jsonl"] = inputs.audit_log_jsonl.encode("utf-8")

    manifest = _manifest(inputs, files)
    files["manifest.json"] = json.dumps(manifest, indent=2).encode("utf-8")

    return _zip(files)


def _manifest(
    inputs: EvidencePackInputs, files: dict[str, bytes]
) -> dict[str, Any]:
    return {
        "platform": "ai-security-platform",
        "platform_version": "0.1.0",
        "org_id": str(inputs.org_id),
        "framework": inputs.framework,
        "period_start": inputs.period_start.astimezone(timezone.utc).isoformat(),
        "period_end": inputs.period_end.astimezone(timezone.utc).isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": [
            {
                "path": path,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(files.items())
        ],
    }


# ─────────────────────────────────────────── loaders


async def _load_findings(
    db: AsyncSession, inputs: EvidencePackInputs
) -> list[Finding]:
    stmt = (
        select(Finding)
        .where(Finding.org_id == inputs.org_id)
        .where(Finding.created_at >= inputs.period_start)
        .where(Finding.created_at <= inputs.period_end)
    )
    return list((await db.execute(stmt)).scalars().all())


async def _load_evaluations(
    db: AsyncSession, inputs: EvidencePackInputs
) -> list[Evaluation]:
    stmt = (
        select(Evaluation)
        .where(Evaluation.org_id == inputs.org_id)
        .where(Evaluation.started_at >= inputs.period_start)
        .where(Evaluation.started_at <= inputs.period_end)
    )
    return list((await db.execute(stmt)).scalars().all())


async def _load_policies(
    db: AsyncSession, org_id: uuid.UUID
) -> list[Policy]:
    stmt = select(Policy).where(Policy.org_id == org_id)
    return list((await db.execute(stmt)).scalars().all())


# ─────────────────────────────────────────── serialisers


def _finding_dicts(rows: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "id": str(r.id),
            "evaluation_id": str(r.evaluation_id),
            "asset_id": str(r.asset_id),
            "test_case_id": str(r.test_case_id),
            "title": r.title,
            "category": r.category,
            "severity": r.severity,
            "risk_score": r.risk_score,
            "control_mappings": list(r.control_mappings or []),
            "remediation_status": r.remediation_status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


def _evaluation_rows(rows: list[Evaluation]) -> list[list[str]]:
    return [
        [
            str(r.id),
            str(r.asset_id),
            r.started_at.isoformat() if r.started_at else "",
            r.completed_at.isoformat() if r.completed_at else "",
            r.status,
            str(r.score) if r.score is not None else "",
            str(r.findings_count or 0),
            str(r.critical_findings or 0),
        ]
        for r in rows
    ]


def _policy_dicts(rows: list[Policy]) -> list[dict[str, Any]]:
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "version": r.version,
            "status": r.status,
            "enforcement_level": r.enforcement_level,
            "fail_behavior": r.fail_behavior,
            "judge_enabled": r.judge_enabled,
            "rules_count": len(r.rules or []),
            "classifiers_count": len(r.classifiers or []),
            "tool_allowlist": list(r.tool_allowlist or []),
            "tool_denylist": list(r.tool_denylist or []),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


def _to_jsonl(rows: list[dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    for row in rows:
        buf.write(json.dumps(row, default=str))
        buf.write("\n")
    return buf.getvalue().encode("utf-8")


def _to_csv(header: list[str], rows: list[list[str]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode("utf-8")


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in sorted(files.items()):
            zf.writestr(path, content)
    return buf.getvalue()
