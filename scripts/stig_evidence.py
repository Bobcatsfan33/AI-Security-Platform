"""Render a STIG-style evidence summary from the control matrix (A-5).

A reviewer-facing companion to the OSCAL output: a flat findings table mapping
each control to a CKL-style status and its evidence. Shares the matrix and its
integrity check with generate_oscal.py.

    python scripts/stig_evidence.py --out evidence-summary.md

Pure stdlib; no network.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from generate_oscal import load_matrix, repo_root, validate_matrix

# STIG CKL status vocabulary mapped from our matrix statuses.
_CKL = {
    "implemented": "NotAFinding",
    "partial": "Open",
    "planned": "Open",
    "not_applicable": "Not_Applicable",
}


def render(matrix: dict) -> str:
    lines = [
        f"# {matrix.get('system', 'Platform')} — STIG-style Control Evidence Summary",
        "",
        f"Framework: {matrix.get('framework', '')} ({matrix.get('baseline', '')} baseline)",
        "",
        "| Control | Title | Status | CKL | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for c in sorted(matrix["controls"], key=lambda x: x["id"]):
        ev = "<br>".join(f"`{e}`" for e in c.get("evidence_files", [])) or "—"
        ckl = _CKL.get(c["status"], "Open")
        lines.append(
            f"| {c['id']} | {c.get('title', '')} | {c['status']} | {ckl} | {ev} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--matrix",
        type=Path,
        default=repo_root() / "compliance" / "control_matrix.json",
    )
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()

    matrix = load_matrix(args.matrix)
    errors = validate_matrix(matrix, repo_root())
    if errors:
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    md = render(matrix)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(md)
        print(f"wrote STIG evidence summary → {args.out}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
