"""The committed efficacy report must describe the detectors that exist now.

`docs/enterprise-readiness.json` lists `docs/evidence/p15/efficacy-report.json`
as evidence, and `scripts/verify_enterprise_readiness.py` checks that the path
resolves to a regular file. It has never checked that the file is *current*, and
that gap bit exactly once already: the report was generated at
2026-08-01T14:45:55Z, the multilingual fix (#128) merged at 17:31:25Z, and the
report was never regenerated. For three days the repository shipped evidence
saying multilingual recall was 0.25 while the detectors actually scored 1.00 —
understating itself, but wrong either way, and wrong in a file whose whole
purpose is to be quotable.

A dangling evidence path fails the build. A stale one now fails it too.

The report already embeds everything needed to detect this: the corpus hashes
and, per surface, the detector-set and detector-config hashes it was measured
against. If any of them has moved, the numbers in the report were produced by
code that no longer exists, and the fix is to re-run:

    cd backend && python scripts/run_efficacy.py \\
      --manifest app/efficacy/corpora/synthetic-text-test.manifest.json \\
      --manifest app/efficacy/corpora/synthetic-events-test.manifest.json \\
      --out ../docs/evidence/p15 --name efficacy

This deliberately does NOT re-score anything. It compares bindings, so it stays
fast and it cannot itself drift from the harness.

Scope note: this guards `docs/evidence/p15/`, the current-state report. It must
never be pointed at `docs/evidence/p15b/`, which is a frozen point-in-time
before/after record of the multilingual fix. Regenerating a stale current-state
report corrects a bug; regenerating a frozen receipt would falsify history.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from app.efficacy.manifest import load_manifest
from app.efficacy.surfaces import default_surfaces

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
REPORT = REPO_ROOT / "docs" / "evidence" / "p15" / "efficacy-report.json"
CORPORA = REPO_ROOT / "backend" / "app" / "efficacy" / "corpora"
MANIFESTS = (
    CORPORA / "synthetic-text-test.manifest.json",
    CORPORA / "synthetic-events-test.manifest.json",
)

REGENERATE = (
    "docs/evidence/p15/efficacy-report.json is stale — it was measured against "
    "code or corpora that have since changed. Re-run:\n"
    "  cd backend && python scripts/run_efficacy.py "
    "--manifest app/efficacy/corpora/synthetic-text-test.manifest.json "
    "--manifest app/efficacy/corpora/synthetic-events-test.manifest.json "
    "--out ../docs/evidence/p15 --name efficacy"
)


@pytest.fixture(scope="module")
def report() -> dict:
    if not REPORT.is_file():
        pytest.fail(f"{REPORT} is missing; the readiness manifest names it as evidence")
    return json.loads(REPORT.read_text(encoding="utf-8"))


def test_the_report_was_measured_against_the_current_detectors(report: dict) -> None:
    """A detector change without a re-run leaves quotable numbers that are lies."""
    recorded = {binding["surface"]: binding for binding in report["bindings"]["surfaces"]}
    current = {surface.name: surface.binding() for surface in default_surfaces()}

    assert recorded.keys() == current.keys(), (
        f"the report covers surfaces {sorted(recorded)} but the harness now promotes "
        f"{sorted(current)}.\n{REGENERATE}"
    )
    for name, expected in current.items():
        assert recorded[name] == expected, (
            f"surface {name!r} has changed since the report was generated "
            f"(report: {recorded[name]}, current: {expected}).\n{REGENERATE}"
        )


def test_the_report_was_measured_against_the_current_corpora(report: dict) -> None:
    """Corpora are hash-pinned; a re-authored case invalidates the numbers."""
    recorded = {corpus["id"]: corpus["sha256"] for corpus in report["bindings"]["corpora"]}
    # load_manifest re-hashes the corpus file and refuses on mismatch, so this
    # also proves the pinned hashes still describe the bytes on disk.
    current = {manifest.id: manifest.sha256 for manifest in (load_manifest(p) for p in MANIFESTS)}

    assert recorded == current, f"corpus hashes have moved.\n{REGENERATE}"


def test_the_report_still_refuses_to_be_quoted_as_real_efficacy(report: dict) -> None:
    """Regenerating must never quietly upgrade the evidence class.

    A re-run that flipped these would turn synthetic numbers into a claim about
    real traffic, which is the exact failure the whole manifest exists to stop.
    """
    assert report["evidence_class"] == "synthetic-demonstration"
    assert report["independent_evaluation"] is False
    assert report["representative"] is False
