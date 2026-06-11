"""Provision a model artifact from a checksum-pinned release URL (Phase 1A).

The Stage-2 ONNX model is too large to commit, so it ships as a release
artifact downloaded at startup and **verified against a pinned SHA-256** before
use — a tampered or truncated download is rejected, never silently loaded.

Supported sources: ``file://`` (local / tests) and ``http(s)://`` (a GitHub
release or object store). Downloads stream to a temp file so a multi-hundred-MB
model never lands in memory, and a verified artifact is cached so restarts
don't re-download.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path

logger = logging.getLogger("platform.provisioning")

_CHUNK = 1 << 20  # 1 MiB


class ModelProvisionError(RuntimeError):
    """Raised when an artifact can't be fetched or fails checksum verification."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def provision_artifact(*, url: str, sha256: str, dest: Path, timeout: float = 300.0) -> Path:
    """Ensure ``dest`` holds the artifact at ``url`` with the given SHA-256.

    Returns the cached path. Re-uses an existing ``dest`` when its checksum
    already matches (no re-download). Raises :class:`ModelProvisionError` on a
    checksum mismatch or an unsupported URL scheme — the caller decides whether
    to fail open (heuristic fallback) or hard.
    """
    if not url:
        raise ModelProvisionError("no artifact url configured")

    if dest.exists() and sha256 and _sha256(dest) == sha256:
        logger.info("model_artifact_cache_hit", extra={"dest": str(dest)})
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        if url.startswith("file://"):
            shutil.copyfile(url[len("file://") :], tmp)
        elif url.startswith(("http://", "https://")):
            import httpx

            with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as resp:
                resp.raise_for_status()
                with tmp.open("wb") as f:
                    for chunk in resp.iter_bytes(_CHUNK):
                        f.write(chunk)
        else:
            raise ModelProvisionError(f"unsupported artifact url scheme: {url!r}")

        got = _sha256(tmp)
        if sha256 and got != sha256:
            raise ModelProvisionError(f"checksum mismatch for {url}: expected {sha256}, got {got}")
        tmp.replace(dest)
        logger.info("model_artifact_provisioned", extra={"url": url, "dest": str(dest)})
        return dest
    finally:
        tmp.unlink(missing_ok=True)
