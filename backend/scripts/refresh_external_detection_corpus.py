#!/usr/bin/env python3
"""Rebuild the pinned external prompt-injection evaluation corpus.

Run from the repository root with:

    uv run --with pyarrow backend/scripts/refresh_external_detection_corpus.py

The source revision and raw Parquet digest are immutable inputs. A source-side
change therefore fails instead of silently changing the benchmark.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import urllib.request
from pathlib import Path

import pyarrow.parquet as parquet

SOURCE_DATASET = "deepset/prompt-injections"
SOURCE_REVISION = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
SOURCE_FILE = "data/test-00000-of-00001-701d16158af87368.parquet"
SOURCE_SHA256 = "39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e"
SOURCE_URL = (
    f"https://huggingface.co/datasets/{SOURCE_DATASET}/resolve/{SOURCE_REVISION}/{SOURCE_FILE}"
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "app" / "benchmark" / "external"
CORPUS_PATH = OUTPUT_DIR / "deepset_prompt_injections_test.jsonl"
MANIFEST_PATH = OUTPUT_DIR / "deepset_prompt_injections_test.manifest.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aisp-efficacy-") as directory:
        source_path = Path(directory) / "source.parquet"
        with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:
            raw = response.read()
        if _sha256(raw) != SOURCE_SHA256:
            raise SystemExit(
                "source corpus digest changed; review the upstream revision explicitly"
            )
        source_path.write_bytes(raw)

        table = parquet.read_table(source_path, columns=["text", "label"])
        rows = []
        attack_count = 0
        benign_count = 0
        for index, row in enumerate(table.to_pylist()):
            is_attack = int(row["label"]) == 1
            attack_count += int(is_attack)
            benign_count += int(not is_attack)
            rows.append(
                {
                    "id": f"deepset-test-{index:03d}",
                    "text": str(row["text"]),
                    "label": "attack" if is_attack else "benign",
                    "attack_class": "prompt_injection" if is_attack else "",
                }
            )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    corpus = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows
    ).encode()
    CORPUS_PATH.write_bytes(corpus)
    manifest = {
        "schema_version": 1,
        "dataset": SOURCE_DATASET,
        "source_revision": SOURCE_REVISION,
        "source_file": SOURCE_FILE,
        "source_url": SOURCE_URL,
        "source_sha256": SOURCE_SHA256,
        "output_sha256": _sha256(corpus),
        # Upstream's top-level card says Apache-2.0 while dataset_info says
        # CC-BY-4.0. Treat the more restrictive declaration as authoritative.
        "license": "CC-BY-4.0",
        "license_note": (
            "Conservative selection: upstream card metadata also declares Apache-2.0, "
            "but dataset_info declares CC-BY-4.0."
        ),
        "attribution": "deepset/prompt-injections, adapted to normalized JSONL",
        "adaptation": (
            "Column names normalized; labels mapped from 0/1 to benign/attack; text unchanged."
        ),
        "license_url": (
            f"https://huggingface.co/datasets/{SOURCE_DATASET}/blob/" f"{SOURCE_REVISION}/README.md"
        ),
        "rows": len(rows),
        "attacks": attack_count,
        "benign": benign_count,
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(rows)} rows ({attack_count} attacks, {benign_count} benign)")


if __name__ == "__main__":
    main()
