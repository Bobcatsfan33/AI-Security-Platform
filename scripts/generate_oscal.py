"""Generate an OSCAL component definition from the first-party control matrix,
and enforce the matrix's integrity rule (A-5).

The platform sells ATO evidence packs; this produces ours. The integrity rule —
**no 'implemented' or 'partial' control without an evidence_files entry that
exists in the repo** — is enforced here, so a control can't claim coverage it
can't show. Run in CI to both validate and emit the evidence artifact.

    python scripts/generate_oscal.py                 # validate only
    python scripts/generate_oscal.py --out oscal.json # validate + render OSCAL

Pure stdlib; no network. Deterministic: UUIDs are derived (uuid5) from control
ids so re-runs produce identical output.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

# Stable namespace so generated UUIDs are reproducible across runs/machines.
_NS = uuid.UUID("8f5d2e2a-0000-5a5a-9c9c-a15ec0de0001")

_REQUIRES_EVIDENCE = {"implemented", "partial"}
_ALLOWED = {"implemented", "partial", "planned", "not_applicable"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_matrix(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def validate_matrix(matrix: dict[str, Any], root: Path) -> list[str]:
    """Return a list of integrity violations (empty == valid)."""
    errors: list[str] = []
    seen: set[str] = set()
    for c in matrix.get("controls", []):
        cid = c.get("id", "<missing id>")
        if cid in seen:
            errors.append(f"{cid}: duplicate control id")
        seen.add(cid)

        status = c.get("status")
        if status not in _ALLOWED:
            errors.append(f"{cid}: status {status!r} not in {sorted(_ALLOWED)}")

        evidence = c.get("evidence_files", [])
        if status in _REQUIRES_EVIDENCE and not evidence:
            errors.append(
                f"{cid}: status {status!r} requires at least one evidence file"
            )
        for ev in evidence:
            if not (root / ev).exists():
                errors.append(f"{cid}: evidence file does not exist: {ev}")
    return errors


def _u(*parts: str) -> str:
    return str(uuid.uuid5(_NS, ":".join(parts)))


def to_oscal(matrix: dict[str, Any], *, last_modified: str) -> dict[str, Any]:
    """Render the matrix as a minimal-but-valid OSCAL component definition."""
    source = matrix.get("framework", "NIST SP 800-53 Rev 5")
    implemented_reqs = []
    for c in matrix["controls"]:
        cid = c["id"]
        implemented_reqs.append(
            {
                "uuid": _u("req", cid),
                "control-id": cid.lower(),
                "description": c.get("narrative", ""),
                "props": [
                    {
                        "name": "implementation-status",
                        "value": c["status"],
                        "ns": "https://aisp/oscal",
                    },
                    {
                        "name": "control-title",
                        "value": c.get("title", ""),
                        "ns": "https://aisp/oscal",
                    },
                ],
                "links": [
                    {"href": ev, "rel": "evidence"}
                    for ev in c.get("evidence_files", [])
                ],
            }
        )
    return {
        "component-definition": {
            "uuid": _u("component-definition", matrix.get("system", "platform")),
            "metadata": {
                "title": f"{matrix.get('system', 'Platform')} — Control Implementation",
                "last-modified": last_modified,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "components": [
                {
                    "uuid": _u("component", matrix.get("system", "platform")),
                    "type": "software",
                    "title": matrix.get("system", "Platform"),
                    "description": matrix.get("notes", ""),
                    "control-implementations": [
                        {
                            "uuid": _u("control-implementation", source),
                            "source": source,
                            "description": f"{matrix.get('baseline', '')} baseline",
                            "implemented-requirements": implemented_reqs,
                        }
                    ],
                }
            ],
        }
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--matrix",
        type=Path,
        default=repo_root() / "compliance" / "control_matrix.json",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write OSCAL JSON here (else validate only)",
    )
    p.add_argument(
        "--last-modified",
        default="2026-01-01T00:00:00Z",
        help="OSCAL metadata timestamp (kept fixed for reproducible output)",
    )
    args = p.parse_args()

    matrix = load_matrix(args.matrix)
    errors = validate_matrix(matrix, repo_root())
    if errors:
        print("control matrix integrity FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    counts: dict[str, int] = {}
    for c in matrix["controls"]:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    print(f"control matrix OK: {len(matrix['controls'])} controls {counts}")

    if args.out:
        oscal = to_oscal(matrix, last_modified=args.last_modified)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(oscal, indent=2, sort_keys=True) + "\n")
        print(f"wrote OSCAL component definition → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
