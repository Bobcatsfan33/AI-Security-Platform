"""The repository states its version in four places. They must agree.

Same reasoning as the licence guard next door: a version is not a string in a
file, it is the same claim repeated across every artifact someone might read —
the backend distribution, the Python SDK, the Node SDK, and the frontend
package. Each is edited by a different reflex at a different time, so they
drift, and a release that ships a 0.2.0 backend with a 0.1.0 SDK has told two
different stories about what you installed.

Cheap to check, impossible to notice by eye, and the failure only shows up
after the tag is public. Worth pinning.
"""

from __future__ import annotations

import json
import pathlib
import re
import tomllib

import pytest

pytestmark = pytest.mark.unit

_ROOT = pathlib.Path(__file__).resolve().parents[3]

_PYPROJECTS = (
    _ROOT / "backend" / "pyproject.toml",
    _ROOT / "sdks" / "python" / "pyproject.toml",
)
_PACKAGE_JSONS = (
    _ROOT / "sdks" / "node" / "package.json",
    _ROOT / "frontend" / "package.json",
)
_CHANGELOG = _ROOT / "CHANGELOG.md"

# Semantic versions only. A four-part or date-like version here would sail past
# the release workflow's own tag validator and fail at publish time instead.
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?$")


def _declared_versions() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _PYPROJECTS:
        found[str(path.relative_to(_ROOT))] = tomllib.loads(path.read_text())["project"]["version"]
    for path in _PACKAGE_JSONS:
        found[str(path.relative_to(_ROOT))] = json.loads(path.read_text())["version"]
    return found


def test_every_component_declares_the_same_version() -> None:
    versions = _declared_versions()
    distinct = set(versions.values())

    assert len(distinct) == 1, "component versions have drifted apart:\n  " + "\n  ".join(
        f"{path}: {version}" for path, version in sorted(versions.items())
    )


@pytest.mark.parametrize("path", sorted(_declared_versions()))
def test_each_version_is_a_semantic_version(path: str) -> None:
    """The release workflow refuses a tag that is not semver. Catching it here
    means finding out before the tag is public rather than after."""
    version = _declared_versions()[path]

    assert _SEMVER.match(version), f"{path}: {version!r} is not a semantic version"


def test_the_changelog_documents_the_current_version() -> None:
    """A release whose changelog does not mention it is a release nobody can
    read. This is the one that catches a version bump made in isolation."""
    version = next(iter(set(_declared_versions().values())))

    assert _CHANGELOG.is_file(), "CHANGELOG.md is missing"
    assert f"## [{version}]" in _CHANGELOG.read_text(), (
        f"CHANGELOG.md has no '## [{version}]' section — the declared version "
        "was bumped without a changelog entry"
    )


def test_the_changelog_still_states_the_limitations() -> None:
    """The release notes mirror the README's Status section by design. If the
    honest part gets quietly dropped in a future edit, the changelog becomes
    marketing and this fails."""
    text = _CHANGELOG.read_text()

    assert "Known limitations" in text
    assert "synthetic" in text.lower()
    assert "not-approved" in text
