"""Regression checks for the executable software-supply-chain contract."""

from __future__ import annotations

import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_DOCKERFILES = (
    _ROOT / "backend" / "Dockerfile",
    _ROOT / "frontend" / "Dockerfile",
    _ROOT / "runtime-agent" / "Dockerfile",
)
_DIGEST = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_ACTION = re.compile(r"^\s*-\s+uses:\s+([^#\s]+)", re.MULTILINE)


def test_every_container_build_base_is_digest_pinned() -> None:
    for dockerfile in _DOCKERFILES:
        args = [
            line.split("=", 1)[1]
            for line in dockerfile.read_text().splitlines()
            if line.startswith("ARG ") and "_IMAGE=" in line
        ]
        assert args, f"{dockerfile.relative_to(_ROOT)} has no pinned image argument"
        assert all(_DIGEST.fullmatch(value) for value in args), (
            f"{dockerfile.relative_to(_ROOT)} has a mutable build base: {args}"
        )


def test_workflows_use_only_commit_pinned_actions() -> None:
    workflows = "\n".join(
        path.read_text() for path in sorted(_WORKFLOW_DIR.glob("*.yml"))
    )
    actions = _ACTION.findall(workflows)
    assert actions
    mutable = [action for action in actions if not re.search(r"@[0-9a-f]{40}$", action)]
    assert not mutable, f"workflows have mutable action references: {mutable}"
    assert "security-reusable.yml@main" not in workflows


def test_release_requires_approval_and_verifies_exact_identity() -> None:
    workflow = (_WORKFLOW_DIR / "security.yml").read_text()
    for required in (
        "environment: production-release",
        "startsWith(github.ref, 'refs/tags/v')",
        "git merge-base --is-ancestor",
        "cosign verify",
        "cosign verify-attestation",
        "actions/attest-build-provenance@",
        "retention-days: 90",
    ):
        assert required in workflow


def test_production_charts_require_digest_identity() -> None:
    for chart in ("ai-security-platform", "ai-security-agent"):
        chart_root = _ROOT / "deploy" / "helm" / chart
        validation = (chart_root / "templates" / "validate.yaml").read_text()
        helper = (chart_root / "templates" / "_helpers.tpl").read_text()
        assert 'regexMatch "^sha256:[a-f0-9]{64}$"' in validation
        assert "image.digest" in validation
        assert "@%s" in helper
