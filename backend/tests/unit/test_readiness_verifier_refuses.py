"""The readiness verifier must refuse every way of overstating the project.

This is the claim the repository is loudest about: the manifest cannot say the
software is ready while the evidence says otherwise, because CI checks. A claim
like that is only worth what its weakest branch is worth, and there was a weak
one — ``deploymentDecision: approved`` was refused while blocking gates were
open, but flipping ``softwareReleaseCandidate`` to ``true`` was accepted. The
README presents the two as peer facts in a single table, so anyone actually
testing the claim would have found the one field that could still lie.

Each test below mutates a copy of the real manifest into a specific
overstatement and asserts the verifier exits non-zero. The positive control runs
first: a checker that rejects everything would pass every other test here while
being useless.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit

_ROOT = pathlib.Path(__file__).resolve().parents[3]
_SCRIPT = _ROOT / "scripts" / "verify_enterprise_readiness.py"
_MANIFEST = _ROOT / "docs" / "enterprise-readiness.json"


@pytest.fixture
def sandbox(tmp_path):
    """A throwaway copy of the repository's manifest + evidence layout.

    The verifier resolves evidence paths relative to the repository root, so the
    sandbox mirrors enough of the tree for a valid manifest to stay valid. It
    never writes to the real manifest — a test that mutated the live file and
    crashed would leave the repository asserting something false.
    """
    # The verifier resolves everything from parents[1] of its own file, i.e.
    # it expects to live in <root>/scripts/. Mirror that exactly — an earlier
    # cut of this fixture put the script at the root, so it looked for the
    # manifest one directory too high, failed with ENOENT, and three "refusal"
    # tests passed because the file was MISSING rather than because the
    # overstatement was refused. A false pass on the tests guarding the
    # project's loudest claim.
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    shutil.copy(_SCRIPT, root / "scripts" / "verify.py")
    shutil.copy(_MANIFEST, root / "docs" / "enterprise-readiness.json")

    manifest = json.loads(_MANIFEST.read_text())
    for control in manifest["controls"]:
        for path in control["evidence"]:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("evidence stand-in\n", encoding="utf-8")
    for gate in manifest["externalGates"]:
        for path in gate.get("evidence", []):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("evidence stand-in\n", encoding="utf-8")
    return root


def _run(root: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "scripts/verify.py"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _mutate(root: pathlib.Path, change) -> None:
    path = root / "docs" / "enterprise-readiness.json"
    manifest = json.loads(path.read_text())
    change(manifest)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def test_the_unmodified_manifest_is_accepted(sandbox):
    """Positive control. Without it, a verifier that rejected everything would
    sail through every refusal test below."""
    result = _run(sandbox)

    assert result.returncode == 0, result.stdout + result.stderr


def test_it_refuses_an_approved_deployment_decision(sandbox):
    _mutate(sandbox, lambda m: m["assessment"].update(deploymentDecision="approved"))

    result = _run(sandbox)

    assert result.returncode != 0
    assert "cannot be approved" in (result.stdout + result.stderr)


def test_it_refuses_a_release_candidate_claim(sandbox):
    """The branch that was missing. `softwareReleaseCandidate` is a second
    approval claim and was entirely unguarded."""
    _mutate(sandbox, lambda m: m["assessment"].update(softwareReleaseCandidate=True))

    result = _run(sandbox)

    assert result.returncode != 0
    assert "softwareReleaseCandidate" in (result.stdout + result.stderr)


def test_it_refuses_evidence_that_does_not_exist(sandbox):
    """An evidence path is a pointer at something checkable. A dangling one is
    the most comfortable kind of lie: it looks like rigour."""
    _mutate(sandbox, lambda m: m["controls"][0]["evidence"].append("docs/NOT-A-REAL-FILE.md"))

    result = _run(sandbox)

    assert result.returncode != 0


def test_it_refuses_closing_a_blocking_gate_without_evidence(sandbox):
    _mutate(sandbox, lambda m: m["externalGates"][0].update(status="closed"))

    result = _run(sandbox)

    assert result.returncode != 0


def test_it_refuses_a_partial_control_promoted_without_evidence(sandbox):
    def promote(manifest):
        for control in manifest["controls"]:
            if control["status"] == "partial":
                control["status"] = "implemented"
                return
        raise AssertionError("no partial control to promote — fixture assumption broken")

    _mutate(sandbox, promote)

    assert _run(sandbox).returncode != 0


def test_it_refuses_an_expired_review_date(sandbox):
    """The manifest is an EXPIRING claim. Evidence that nobody has revisited in
    a year is a snapshot, not a status."""
    _mutate(sandbox, lambda m: m["assessment"].update(reviewBy="2020-01-01"))

    assert _run(sandbox).returncode != 0


def test_the_live_manifest_still_says_not_approved():
    """Not a check on the verifier — a check on the claim the README, the
    release notes, and the badge all make. If this ever fails, those three are
    wrong and need updating in the same commit."""
    assessment = json.loads(_MANIFEST.read_text())["assessment"]

    assert assessment["deploymentDecision"] == "not-approved"
    assert assessment["softwareReleaseCandidate"] is False
