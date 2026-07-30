"""Load immutable, license-traceable third-party detection corpora."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.benchmark.corpus import CorpusCase

_DATA_DIR = Path(__file__).with_name("external")
_CORPUS_PATH = _DATA_DIR / "deepset_prompt_injections_test.jsonl"
_MANIFEST_PATH = _DATA_DIR / "deepset_prompt_injections_test.manifest.json"


def external_corpus_manifest() -> dict[str, Any]:
    return json.loads(_MANIFEST_PATH.read_text())


def load_external_prompt_injection_corpus() -> tuple[CorpusCase, ...]:
    """Load the pinned, conservatively CC-BY-4.0 deepset split and verify its digest."""

    raw = _CORPUS_PATH.read_bytes()
    manifest = external_corpus_manifest()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != manifest["output_sha256"]:
        raise RuntimeError(
            "external efficacy corpus digest mismatch; regenerate or restore the reviewed artifact"
        )

    cases: list[CorpusCase] = []
    for line_number, line in enumerate(raw.decode().splitlines(), start=1):
        row = json.loads(line)
        label = row.get("label")
        if label not in {"attack", "benign"}:
            raise RuntimeError(f"external efficacy corpus line {line_number} has invalid label")
        cases.append(
            CorpusCase(
                text=str(row["text"]),
                label=label,
                attack_class=str(row.get("attack_class", "")),
            )
        )
    if len(cases) != manifest["rows"]:
        raise RuntimeError("external efficacy corpus row count does not match its manifest")
    return tuple(cases)
