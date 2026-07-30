#!/usr/bin/env python3
"""Fail closed when enterprise-readiness evidence is missing, stale, or misleading."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs" / "enterprise-readiness.json"
REQUIRED_CONTROLS = {
    "GOV-01",
    "SDLC-01",
    "APPSEC-01",
    "SUPPLY-01",
    "IAM-01",
    "CRYPTO-01",
    "DATA-01",
    "RES-01",
    "OBS-01",
    "IR-01",
    "VM-01",
    "AIRISK-01",
}
REQUIRED_FRAMEWORKS = {
    "nist-ssdf-1.1",
    "slsa-1.2",
    "owasp-asvs-5.0.0",
    "csa-ccm-caiq-4.1",
    "nist-ai-rmf-1.0",
    "csa-ai-caiq-1.0.2",
}


def fail(message: str) -> None:
    raise ValueError(message)


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def list_value(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def text_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value


def unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        fail(f"{label} contains duplicates")


def date_value(value: Any, label: str) -> dt.date:
    try:
        return dt.date.fromisoformat(text_value(value, label))
    except ValueError as error:
        fail(f"{label} must be an ISO-8601 date: {error}")


def evidence_path(value: Any, label: str) -> str:
    relative = pathlib.PurePosixPath(text_value(value, label))
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"{label} must be a repository-relative path without '..'")
    candidate = ROOT.joinpath(*relative.parts)
    if candidate.is_symlink() or not candidate.is_file():
        fail(f"{label} does not name a regular, non-symlink repository file: {relative}")
    return relative.as_posix()


def verify(manifest: pathlib.Path = DEFAULT_MANIFEST) -> None:
    document = object_value(json.loads(manifest.read_text(encoding="utf-8")), "manifest")
    if document.get("schemaVersion") != 1:
        fail("schemaVersion must equal 1")
    text_value(document.get("product"), "product")
    text_value(document.get("repository"), "repository")

    assessment = object_value(document.get("assessment"), "assessment")
    as_of = date_value(assessment.get("asOf"), "assessment.asOf")
    review_by = date_value(assessment.get("reviewBy"), "assessment.reviewBy")
    if review_by < as_of:
        fail("assessment.reviewBy must not precede assessment.asOf")
    if dt.datetime.now(dt.timezone.utc).date() > review_by:
        fail(f"enterprise readiness evidence expired on {review_by.isoformat()}")
    decision = assessment.get("deploymentDecision")
    if decision not in {"not-approved", "approved"}:
        fail("assessment.deploymentDecision must be not-approved or approved")
    if not isinstance(assessment.get("softwareReleaseCandidate"), bool):
        fail("assessment.softwareReleaseCandidate must be boolean")
    text_value(assessment.get("decisionReason"), "assessment.decisionReason")

    frameworks = [
        object_value(item, f"frameworks[{index}]")
        for index, item in enumerate(list_value(document.get("frameworks"), "frameworks"))
    ]
    framework_ids = [text_value(item.get("id"), "framework.id") for item in frameworks]
    unique(framework_ids, "framework ids")
    if set(framework_ids) != REQUIRED_FRAMEWORKS:
        fail(f"framework ids must equal {sorted(REQUIRED_FRAMEWORKS)}")
    for framework in frameworks:
        framework_id = framework["id"]
        text_value(framework.get("name"), f"framework {framework_id}.name")
        text_value(framework.get("version"), f"framework {framework_id}.version")
        if not text_value(framework.get("url"), f"framework {framework_id}.url").startswith(
            "https://"
        ):
            fail(f"framework {framework_id}.url must use HTTPS")

    controls = [
        object_value(item, f"controls[{index}]")
        for index, item in enumerate(list_value(document.get("controls"), "controls"))
    ]
    control_ids = [text_value(item.get("id"), "control.id") for item in controls]
    unique(control_ids, "control ids")
    if set(control_ids) != REQUIRED_CONTROLS:
        fail(f"control ids must equal {sorted(REQUIRED_CONTROLS)}")
    incomplete_controls = 0
    for control in controls:
        control_id = control["id"]
        text_value(control.get("title"), f"control {control_id}.title")
        status = control.get("status")
        if status not in {"implemented", "partial", "not-applicable"}:
            fail(f"control {control_id}.status is invalid")
        mapped = [
            text_value(item, f"control {control_id}.frameworks")
            for item in list_value(control.get("frameworks"), f"control {control_id}.frameworks")
        ]
        unique(mapped, f"control {control_id}.frameworks")
        if not mapped or not set(mapped).issubset(REQUIRED_FRAMEWORKS):
            fail(f"control {control_id} must map only to declared frameworks")
        evidence = [
            evidence_path(item, f"control {control_id}.evidence")
            for item in list_value(control.get("evidence"), f"control {control_id}.evidence")
        ]
        unique(evidence, f"control {control_id}.evidence")
        gaps = [
            text_value(item, f"control {control_id}.gaps")
            for item in list_value(control.get("gaps"), f"control {control_id}.gaps")
        ]
        if status in {"implemented", "partial"} and not evidence:
            fail(f"control {control_id} requires evidence")
        if status == "implemented" and gaps:
            fail(f"implemented control {control_id} cannot contain gaps")
        if status == "partial" and not gaps:
            fail(f"partial control {control_id} must name its gaps")
        if status == "partial":
            incomplete_controls += 1

    gates = [
        object_value(item, f"externalGates[{index}]")
        for index, item in enumerate(
            list_value(document.get("externalGates"), "externalGates")
        )
    ]
    if not gates:
        fail("externalGates must not be empty")
    gate_ids = [text_value(item.get("id"), "external gate id") for item in gates]
    unique(gate_ids, "external gate ids")
    open_blocking = 0
    for gate in gates:
        gate_id = gate["id"]
        text_value(gate.get("title"), f"gate {gate_id}.title")
        if gate.get("status") not in {"open", "complete"}:
            fail(f"gate {gate_id}.status must be open or complete")
        if not isinstance(gate.get("blocking"), bool):
            fail(f"gate {gate_id}.blocking must be boolean")
        text_value(gate.get("ownerRole"), f"gate {gate_id}.ownerRole")
        text_value(gate.get("acceptanceCriteria"), f"gate {gate_id}.acceptanceCriteria")
        evidence = [
            evidence_path(item, f"gate {gate_id}.evidence")
            for item in list_value(gate.get("evidence"), f"gate {gate_id}.evidence")
        ]
        unique(evidence, f"gate {gate_id}.evidence")
        if gate["status"] == "complete" and not evidence:
            fail(f"complete gate {gate_id} requires retained evidence")
        if gate["status"] == "open" and gate["blocking"]:
            open_blocking += 1

    if decision == "approved" and (open_blocking or incomplete_controls):
        fail("deploymentDecision cannot be approved while controls or blocking gates remain open")
    if open_blocking and decision != "not-approved":
        fail("open blocking gates require deploymentDecision=not-approved")

    print(
        "enterprise readiness manifest valid: "
        f"{len(controls)} controls, {open_blocking} open blocking gates, "
        f"decision={decision}, reviewBy={review_by.isoformat()}"
    )


if __name__ == "__main__":
    try:
        if len(sys.argv) > 2:
            fail("usage: verify_enterprise_readiness.py [manifest.json]")
        selected = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_MANIFEST
        verify(selected)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"enterprise readiness verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
