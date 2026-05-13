"""Unit tests for the compliance evidence-pack builder.

We don't hit a real DB — the loaders are monkey-patched to return
canned rows so we test the ZIP shape, manifest hashing, and
framework-control mapping integrity.
"""

from __future__ import annotations

import asyncio
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any

import pytest

from app.compliance import evidence_pack as ep
from app.compliance.evidence_pack import (
    CONTROL_MAPPINGS,
    EvidencePackInputs,
    build_pack,
)


@pytest.fixture
def _patch_loaders(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _findings(db: Any, inputs: Any) -> list[Any]:
        return []

    async def _evaluations(db: Any, inputs: Any) -> list[Any]:
        return []

    async def _policies(db: Any, org_id: Any) -> list[Any]:
        return []

    monkeypatch.setattr(ep, "_load_findings", _findings)
    monkeypatch.setattr(ep, "_load_evaluations", _evaluations)
    monkeypatch.setattr(ep, "_load_policies", _policies)


def test_build_pack_zip_contains_expected_files(_patch_loaders: None) -> None:
    inputs = EvidencePackInputs(
        org_id=uuid.uuid4(),
        framework="soc2",
        period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 4, 1, tzinfo=timezone.utc),
        audit_log_jsonl='{"event": "fake"}\n',
    )
    blob = asyncio.run(build_pack(db=None, inputs=inputs))
    zf = zipfile.ZipFile(io.BytesIO(blob))
    names = sorted(zf.namelist())
    assert "manifest.json" in names
    assert "controls/soc2.json" in names
    assert "findings.jsonl" in names
    assert "evaluations.csv" in names
    assert "policies.json" in names
    assert "audit_log.jsonl" in names


def test_manifest_lists_files_with_hashes(_patch_loaders: None) -> None:
    inputs = EvidencePackInputs(
        org_id=uuid.uuid4(),
        framework="iso27001",
        period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    blob = asyncio.run(build_pack(db=None, inputs=inputs))
    zf = zipfile.ZipFile(io.BytesIO(blob))
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["framework"] == "iso27001"
    assert manifest["platform"] == "ai-security-platform"
    file_paths = [f["path"] for f in manifest["files"]]
    assert "controls/iso27001.json" in file_paths
    for entry in manifest["files"]:
        assert len(entry["sha256"]) == 64
        assert entry["size_bytes"] >= 0


def test_unsupported_framework_raises(_patch_loaders: None) -> None:
    inputs = EvidencePackInputs(
        org_id=uuid.uuid4(),
        framework="hipaa",  # type: ignore[arg-type]
        period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(ValueError):
        asyncio.run(build_pack(db=None, inputs=inputs))


def test_control_mappings_well_formed() -> None:
    for fw, controls in CONTROL_MAPPINGS.items():
        assert controls, f"{fw} has no controls"
        for cid, c in controls.items():
            assert isinstance(cid, str)
            assert "title" in c and "evidence" in c


def test_each_framework_serializes_to_valid_json(_patch_loaders: None) -> None:
    for fw in CONTROL_MAPPINGS:
        inputs = EvidencePackInputs(
            org_id=uuid.uuid4(),
            framework=fw,  # type: ignore[arg-type]
            period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        blob = asyncio.run(build_pack(db=None, inputs=inputs))
        zf = zipfile.ZipFile(io.BytesIO(blob))
        # Round-trip the controls file as JSON
        controls_data = json.loads(zf.read(f"controls/{fw}.json"))
        assert set(controls_data.keys()) == set(CONTROL_MAPPINGS[fw].keys())
