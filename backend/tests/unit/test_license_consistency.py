"""The repository states its license in more than one place. They must agree.

A license is not a string in a file, it is the same claim repeated across every
artifact a consumer might read: the root ``LICENSE``, the Python distribution
metadata, the two SDK package manifests, the README section a human lands on,
and the roadmap's per-area posture table. Each of those is edited by a
different reflex at a different time, so they drift silently — and a repository
that says Apache-2.0 in its README and BUSL-1.1 in its wheel metadata has, in
practice, told two different things to two different buyers.

These tests are cheap and they are about a claim we cannot verify at runtime,
which is exactly the combination worth pinning. They assert agreement, not
correctness-in-the-abstract: change ``_SPDX`` and every site has to move with
it, deliberately, in one commit.
"""

from __future__ import annotations

import json
import pathlib
import re
import tomllib

import pytest

pytestmark = pytest.mark.unit

_ROOT = pathlib.Path(__file__).resolve().parents[3]

_LICENSE = _ROOT / "LICENSE"
_BACKEND_PYPROJECT = _ROOT / "backend" / "pyproject.toml"
_SDK_PYPROJECT = _ROOT / "sdks" / "python" / "pyproject.toml"
_SDK_PACKAGE_JSON = _ROOT / "sdks" / "node" / "package.json"
_FRONTEND_PACKAGE_JSON = _ROOT / "frontend" / "package.json"
_README = _ROOT / "README.md"
_ROADMAP = _ROOT / "docs" / "ROADMAP.md"
_CORPORA = _ROOT / "backend" / "app" / "efficacy" / "corpora"

# The single canonical SPDX identifier for this repository.
_SPDX = "Apache-2.0"
_COPYRIGHT = "Copyright 2026 Ryan Wallace"

# Superseded licenses. Any of these reappearing as an assertion about *this*
# repository means a partial revert or a stale copy — not a valid state.
_SUPERSEDED = ("BUSL-1.1", "Business Source License")


def _project_license(pyproject: pathlib.Path) -> str:
    """The declared license out of a PEP 621 ``[project]`` table.

    Accepts both the ``license = "SPDX"`` and ``license = { text = "SPDX" }``
    spellings so this test survives a PEP 639 migration without going green
    for the wrong reason.
    """
    declared = tomllib.loads(pyproject.read_text())["project"]["license"]
    return declared if isinstance(declared, str) else declared["text"]


def test_license_file_is_apache_2_0() -> None:
    lines = _LICENSE.read_text().splitlines()
    assert lines[0].strip() == "Apache License", lines[0]
    assert lines[1].strip() == "Version 2.0, January 2004", lines[1]


def test_license_file_names_the_copyright_holder() -> None:
    assert _COPYRIGHT in _LICENSE.read_text()


def test_backend_distribution_metadata_matches_license_file() -> None:
    assert _project_license(_BACKEND_PYPROJECT) == _SPDX


def test_sdk_manifests_match_license_file() -> None:
    assert _project_license(_SDK_PYPROJECT) == _SPDX
    assert json.loads(_SDK_PACKAGE_JSON.read_text())["license"] == _SPDX
    assert json.loads(_FRONTEND_PACKAGE_JSON.read_text())["license"] == _SPDX


def test_readme_license_section_matches_license_file() -> None:
    """The README section a human reads, not just machine metadata."""
    section = _README.read_text().split("## License", 1)
    assert len(section) == 2, "README lost its '## License' section"
    body = section[1]
    assert _SPDX in body
    # The relicense note is allowed to name the superseded license as history;
    # what is not allowed is the section asserting it as the current terms.
    assert "**Apache-2.0**" in body, "README must state the current license in bold"


def test_roadmap_license_posture_table_is_uniform() -> None:
    """Every row of the per-area posture table names the one license."""
    table = _ROADMAP.read_text().split("## License posture per area", 1)
    assert len(table) == 2, "ROADMAP lost its license posture table"
    rows = [
        line
        for line in table[1].splitlines()
        if line.startswith("|") and not line.startswith("|---") and "| Area " not in line
    ]
    assert rows, "license posture table has no rows"
    for row in rows:
        area, declared = (cell.strip() for cell in row.strip("|").split("|"))
        assert declared == _SPDX, f"{area!r} declares {declared!r}, not {_SPDX!r}"


@pytest.mark.parametrize("manifest", sorted(_CORPORA.glob("*.manifest.json")), ids=lambda p: p.name)
def test_first_party_corpora_ship_under_the_repository_license(
    manifest: pathlib.Path,
) -> None:
    """The synthetic corpora are first-party, so their terms are the repo's."""
    declared = json.loads(manifest.read_text())["provenance"]["license"]
    assert declared.startswith(_SPDX), f"{manifest.name}: {declared!r}"


@pytest.mark.parametrize(
    "path",
    [_LICENSE, _BACKEND_PYPROJECT, _SDK_PYPROJECT, _SDK_PACKAGE_JSON, _README],
    ids=lambda p: p.name,
)
def test_no_superseded_license_is_asserted(path: pathlib.Path) -> None:
    """A superseded license may be named as history, never as current terms.

    ``LICENSE`` and the manifests get the strict rule: the string must not
    appear at all. The README is allowed one mention, in the past tense, so
    the relicense is discoverable by someone holding an older checkout.
    """
    text = path.read_text()
    if path == _README:
        assert re.search(
            r"previously licensed BUSL-1\.1", text
        ), "README must record the relicense in the past tense"
        return
    for superseded in _SUPERSEDED:
        assert superseded not in text, f"{path.name} still asserts {superseded}"
