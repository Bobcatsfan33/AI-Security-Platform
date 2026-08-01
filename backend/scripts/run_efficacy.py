#!/usr/bin/env python3
"""Run the efficacy harness and write the report + receipt.

    python -m scripts.run_efficacy \
        --manifest app/efficacy/corpora/synthetic-text-test.manifest.json \
        --manifest app/efficacy/corpora/synthetic-events-test.manifest.json \
        --out ../docs/evidence/p15

Resumable: pass --checkpoint to append verdicts as they are produced and skip
completed cases on a later run.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from app.efficacy.manifest import ManifestError, load_manifest
from app.efficacy.report import build_report, write_report
from app.efficacy.runner import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", required=True, type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--checkpoint", type=pathlib.Path, default=None)
    parser.add_argument(
        "--name",
        default="efficacy",
        help="basename for the emitted report/receipt pair",
    )
    args = parser.parse_args(argv)

    try:
        manifests = [load_manifest(path) for path in args.manifest]
    except ManifestError as exc:
        # A bad manifest is a refusal, not a warning. Continuing with whatever
        # loaded would produce a report describing a corpus set nobody chose.
        print(f"manifest rejected: {exc}", file=sys.stderr)
        return 2

    result = run(manifests, checkpoint=args.checkpoint)
    report = build_report(result)

    json_path = args.out / f"{args.name}-report.json"
    receipt_path = args.out / f"{args.name}-receipt.txt"
    write_report(report, json_path, receipt_path)

    print(receipt_path.read_text(encoding="utf-8"))
    print(f"report : {json_path}")
    print(f"receipt: {receipt_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
