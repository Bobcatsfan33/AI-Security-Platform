"""The dependency locks (GAP-016).

Two locks, one pyproject:

* ``requirements.lock`` — ``--all-extras``, what CI and developers install.
* ``requirements-runtime.lock`` — no extras, what the production image installs.

The split exists because ``backend/Dockerfile``'s runtime stage does
``COPY --from=builder /install /usr/local``: anything installed in the builder
reaches the shipped image. Using the all-extras lock there would put pytest,
ruff, mypy and bandit into production.

These tests guard the properties that make the locks worth having. They are
cheap and they are about the artifact we cryptographically attest, which is a
combination worth keeping.
"""

from __future__ import annotations

import pathlib
import re

import pytest

pytestmark = pytest.mark.unit

_BACKEND = pathlib.Path(__file__).resolve().parents[2]
_FULL_LOCK = _BACKEND / "requirements.lock"
_RUNTIME_LOCK = _BACKEND / "requirements-runtime.lock"
_DOCKERFILE = _BACKEND / "Dockerfile"

# Tooling that must never reach the production image. Not exhaustive — a
# blocklist cannot be — but these are the dev extras declared in pyproject, so
# any of them appearing means the runtime lock was generated with --all-extras.
_DEV_ONLY = (
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "ruff",
    "black",
    "mypy",
    "bandit",
    "factory-boy",
    "freezegun",
    "coverage",
)


def _pinned_packages(lock: pathlib.Path) -> dict[str, str]:
    """name -> version for every pin in a lock file."""
    pins: dict[str, str] = {}
    for line in lock.read_text().splitlines():
        match = re.match(r"^([A-Za-z0-9._-]+)==([^\s\\]+)", line)
        if match:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def test_both_locks_exist() -> None:
    assert _FULL_LOCK.exists(), "run scripts/lock.sh"
    assert _RUNTIME_LOCK.exists(), "run scripts/lock.sh"


def test_every_pin_is_hashed() -> None:
    """A lock without hashes is a version list. --require-hashes is what makes a
    swapped upstream fail the build instead of executing in it."""
    for lock in (_FULL_LOCK, _RUNTIME_LOCK):
        pins = _pinned_packages(lock)
        assert pins, f"{lock.name} has no pins at all"
        hashes = lock.read_text().count("--hash=sha256:")
        assert hashes >= len(pins), (
            f"{lock.name}: {len(pins)} pins but only {hashes} hashes — "
            "regenerate with scripts/lock.sh (it passes --generate-hashes)"
        )


@pytest.mark.parametrize("package", _DEV_ONLY)
def test_the_runtime_lock_carries_no_dev_tooling(package: str) -> None:
    """THE test for the split. The production image installs this lock, so a dev
    package here is a dev package in production — more attack surface, more
    Trivy findings, and a Dockerfile whose "prod deps only" header is a lie.

    Fails if someone regenerates the runtime lock with --all-extras.
    """
    assert package not in _pinned_packages(_RUNTIME_LOCK), (
        f"{package} is in requirements-runtime.lock, which the production image "
        "installs. Regenerate with scripts/lock.sh — the runtime lock takes no "
        "--all-extras."
    )


def test_the_runtime_lock_is_a_subset_of_the_full_lock() -> None:
    """Both come from one pyproject, so runtime is a strict subset — and at the
    SAME versions. A package resolving differently between them would mean the
    thing we test is not the thing we ship.
    """
    full = _pinned_packages(_FULL_LOCK)
    runtime = _pinned_packages(_RUNTIME_LOCK)

    missing = sorted(set(runtime) - set(full))
    assert not missing, f"in the runtime lock but not the full lock: {missing}"

    mismatched = {
        name: (runtime[name], full[name]) for name in runtime if runtime[name] != full[name]
    }
    assert not mismatched, (
        "these packages resolve to different versions in the two locks, so CI "
        f"tests something other than what ships: {mismatched}"
    )


def test_the_full_lock_carries_the_dev_tooling() -> None:
    """The inverse: if the full lock lost its extras, CI would install no test
    runner and the split would be pointless."""
    pins = _pinned_packages(_FULL_LOCK)
    for package in ("pytest", "ruff", "mypy"):
        assert package in pins, f"{package} missing from requirements.lock"


def test_the_dockerfile_installs_from_the_runtime_lock_with_hashes() -> None:
    """The lock only protects the image if the image actually uses it.

    This is the gap that shipped: GAP-016 pinned CI and dev while the Dockerfile
    still did `pip install .` — a floating resolution — and that image is the one
    Trivy scans, the SBOM describes and cosign signs. The pinning claim was
    loudest about the artifact it did not cover.
    """
    dockerfile = _DOCKERFILE.read_text()

    assert "--require-hashes -r requirements-runtime.lock" in dockerfile, (
        "the production image must install from the hashed runtime lock"
    )
    assert "--no-deps ." in dockerfile, (
        "the project itself must install with --no-deps, or pip re-resolves the "
        "dependencies the lock just pinned"
    )
    # A bare `pip install .` (no --no-deps, no -r) into the builder prefix is
    # the floating resolution this fix removed. `--no-deps .` is the legitimate
    # project install and must not trip this.
    floating = [
        line
        for line in dockerfile.splitlines()
        if "pip install" in line
        and "--prefix=/install" in line
        and line.rstrip().endswith(" .")
        and "--no-deps" not in line
    ]
    assert not floating, (
        f"floating resolution in the artifact we attest: {floating}"
    )
