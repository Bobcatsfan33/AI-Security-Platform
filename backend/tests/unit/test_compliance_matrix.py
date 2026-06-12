"""The control matrix is honest, and the OSCAL/STIG generators work (A-5).

Enforces the acceptance rule in the existing pytest gate: no 'implemented' or
'partial' control may claim coverage without an evidence file that actually
exists in the repo.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO / "scripts"))

import generate_oscal as gen  # noqa: E402
import stig_evidence as stig  # noqa: E402

pytestmark = pytest.mark.unit

_MATRIX = gen.load_matrix(_REPO / "compliance" / "control_matrix.json")


def test_matrix_passes_integrity_check():
    """Every implemented/partial control has existing evidence; statuses valid."""
    errors = gen.validate_matrix(_MATRIX, _REPO)
    assert errors == [], "\n".join(errors)


def test_no_implemented_control_without_existing_evidence():
    for c in _MATRIX["controls"]:
        if c["status"] in {"implemented", "partial"}:
            assert c[
                "evidence_files"
            ], f"{c['id']} claims {c['status']} with no evidence"
            for ev in c["evidence_files"]:
                assert (_REPO / ev).exists(), f"{c['id']} evidence missing: {ev}"


def test_oscal_render_is_wellformed_and_deterministic():
    o1 = gen.to_oscal(_MATRIX, last_modified="2026-01-01T00:00:00Z")
    o2 = gen.to_oscal(_MATRIX, last_modified="2026-01-01T00:00:00Z")
    assert o1 == o2  # deterministic (uuid5)
    cd = o1["component-definition"]
    reqs = cd["components"][0]["control-implementations"][0]["implemented-requirements"]
    assert len(reqs) == len(_MATRIX["controls"])
    assert cd["metadata"]["oscal-version"] == "1.1.2"
    # control ids are lowercased per OSCAL convention
    assert {r["control-id"] for r in reqs} == {
        c["id"].lower() for c in _MATRIX["controls"]
    }


def test_validate_catches_a_broken_matrix(tmp_path):
    bad = {
        "controls": [
            {"id": "XX-1", "title": "t", "status": "implemented", "evidence_files": []},
            {
                "id": "XX-2",
                "title": "t",
                "status": "implemented",
                "evidence_files": ["nope/missing.py"],
            },
            {"id": "XX-3", "title": "t", "status": "bogus", "evidence_files": []},
        ]
    }
    errors = gen.validate_matrix(bad, tmp_path)
    assert any("requires at least one evidence file" in e for e in errors)
    assert any("does not exist" in e for e in errors)
    assert any("not in" in e for e in errors)


def test_stig_summary_lists_every_control():
    md = stig.render(_MATRIX)
    for c in _MATRIX["controls"]:
        assert c["id"] in md
    assert "NotAFinding" in md  # at least one implemented control maps to CKL
