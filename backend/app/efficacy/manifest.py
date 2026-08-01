"""Corpus manifests — what was evaluated, where it came from, who labeled it.

A detection number is meaningless without its corpus, and a corpus is
meaningless without its provenance. "97% recall" is a claim about a specific
set of examples that someone chose, obtained under some terms, and labeled by
some protocol. Strip any of those away and the number stops being checkable.

So every field below is REQUIRED, and loading fails rather than defaulting:

* ``provenance`` — where the data came from and under what authorization. A
  corpus nobody is allowed to use is not evidence, it is a liability.
* ``labeling_protocol`` — how ground truth was decided. Metrics computed
  against labels of unknown quality measure the labeler, not the detector.
* ``sha256`` — the exact bytes. Without it a report names a filename, and the
  file behind that name can change.
* ``split`` — train / calibration / test. Declared here so overlap can be
  refused rather than discovered later in someone's else's audit.
* ``representative`` — whether this claims to reflect real deployment traffic.
  Defaults to False and cannot be set True without ``authorization``.

None of this makes a synthetic corpus representative. It makes it honest.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

from app.efficacy.slices import SliceAxis, resolve

# Splits must be disjoint. A case that appears in both what a model was tuned
# on and what it is measured on inflates the measurement by exactly the amount
# nobody can see.
VALID_SPLITS = frozenset({"train", "calibration", "test"})

_REQUIRED_PROVENANCE = ("source", "collected_by", "collected_at", "license", "authorization")
_REQUIRED_LABELING = ("method", "labelers", "adjudication", "inter_annotator_agreement")


class ManifestError(ValueError):
    """A manifest that cannot be trusted to describe what it points at."""


class LeakageError(ManifestError):
    """The same case appears in more than one split.

    Its own type because this is the failure that silently inflates every
    downstream number, and a caller may reasonably want to catch it
    specifically to report which cases overlapped.
    """


@dataclass(frozen=True)
class CorpusCase:
    """One labeled example.

    ``kind`` distinguishes the two evaluated surface shapes: ``text`` cases go
    to the content detectors, ``event_sequence`` cases go to the behavioural
    (attack-graph / anomaly) path. Keeping both in one corpus format is what
    lets a single run cover every promoted detection surface instead of only
    the injection models.
    """

    id: str
    kind: str  # "text" | "event_sequence"
    label: str  # "attack" | "benign"
    payload: dict[str, Any]
    attack_class: str = ""
    slices: tuple[str, ...] = ()

    def content_hash(self) -> str:
        """Identity for leakage detection: the CONTENT, not the id.

        Hashing the id would miss the actual problem — the same example
        included in two splits under two different ids, which is what happens
        when corpora are assembled by copy-paste.
        """
        canonical = json.dumps(
            {"kind": self.kind, "payload": self.payload},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CorpusManifest:
    id: str
    path: pathlib.Path
    sha256: str
    split: str
    provenance: dict[str, str]
    labeling_protocol: dict[str, str]
    slice_axes: tuple[SliceAxis, ...]
    description: str = ""
    # False means: this corpus does NOT claim to reflect real deployment
    # traffic. Every corpus shipped in this repository is synthetic, so every
    # one of them says False, and the report says so on their behalf.
    representative: bool = False
    authorization: str = ""
    cases: tuple[CorpusCase, ...] = field(default_factory=tuple)

    @property
    def is_synthetic(self) -> bool:
        return not self.representative


def _require(mapping: dict[str, Any], keys: tuple[str, ...], where: str, manifest_id: str) -> None:
    missing = [key for key in keys if not str(mapping.get(key, "")).strip()]
    if missing:
        raise ManifestError(
            f"{manifest_id}: {where} is missing required field(s) {missing}. "
            "These are not optional — a metric without provenance and a "
            "labeling protocol is not checkable by anyone but its author."
        )


def _load_cases(path: pathlib.Path, manifest_id: str) -> tuple[CorpusCase, ...]:
    cases: list[CorpusCase] = []
    seen_ids: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ManifestError(
                f"{manifest_id}: {path.name}:{line_number} is not valid JSON: {exc}"
            ) from None
        for key in ("id", "kind", "label", "payload"):
            if key not in record:
                raise ManifestError(f"{manifest_id}: {path.name}:{line_number} lacks {key!r}")
        if record["label"] not in ("attack", "benign"):
            raise ManifestError(
                f"{manifest_id}: {path.name}:{line_number} has label "
                f"{record['label']!r}; expected 'attack' or 'benign'"
            )
        if record["kind"] not in ("text", "event_sequence"):
            raise ManifestError(
                f"{manifest_id}: {path.name}:{line_number} has kind {record['kind']!r}; "
                "expected 'text' or 'event_sequence'"
            )
        if record["id"] in seen_ids:
            raise ManifestError(
                f"{manifest_id}: duplicate case id {record['id']!r} at {path.name}:{line_number}"
            )
        seen_ids.add(record["id"])
        for slice_name in record.get("slices", ()):
            resolve(slice_name)  # raises on an unknown axis
        cases.append(
            CorpusCase(
                id=record["id"],
                kind=record["kind"],
                label=record["label"],
                payload=record["payload"],
                attack_class=record.get("attack_class", ""),
                slices=tuple(record.get("slices", ())),
            )
        )
    if not cases:
        raise ManifestError(f"{manifest_id}: {path.name} contains no cases")
    return tuple(cases)


def load_manifest(manifest_path: pathlib.Path) -> CorpusManifest:
    """Read, validate, and hash-verify one corpus manifest."""
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{manifest_path}: not valid JSON: {exc}") from None

    manifest_id = raw.get("id") or manifest_path.stem
    for key in ("id", "path", "sha256", "split", "provenance", "labeling_protocol", "slice_axes"):
        if key not in raw:
            raise ManifestError(f"{manifest_id}: manifest lacks required key {key!r}")

    if raw["split"] not in VALID_SPLITS:
        raise ManifestError(
            f"{manifest_id}: split {raw['split']!r} is not one of {sorted(VALID_SPLITS)}"
        )

    _require(raw["provenance"], _REQUIRED_PROVENANCE, "provenance", manifest_id)
    _require(raw["labeling_protocol"], _REQUIRED_LABELING, "labeling_protocol", manifest_id)

    representative = bool(raw.get("representative", False))
    authorization = str(raw.get("authorization", "")).strip()
    if representative and not authorization:
        # The one claim that cannot be self-asserted. Marking a corpus
        # representative is what turns a demonstration into evidence, so it
        # requires naming the authority that says it is.
        raise ManifestError(
            f"{manifest_id}: representative=true requires a non-empty 'authorization' "
            "naming who authorized this corpus as representative of real traffic."
        )

    corpus_path = (manifest_path.parent / raw["path"]).resolve()
    if not corpus_path.is_file():
        raise ManifestError(f"{manifest_id}: corpus file {raw['path']!r} does not exist")

    actual = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    if actual != raw["sha256"]:
        raise ManifestError(
            f"{manifest_id}: corpus hash mismatch for {raw['path']!r}.\n"
            f"  manifest declares {raw['sha256']}\n"
            f"  file on disk is   {actual}\n"
            "The manifest describes bytes that are not there. Re-pin it "
            "deliberately — do not edit the corpus and the hash in one motion "
            "without knowing what changed."
        )

    return CorpusManifest(
        id=manifest_id,
        path=corpus_path,
        sha256=actual,
        split=raw["split"],
        provenance=dict(raw["provenance"]),
        labeling_protocol=dict(raw["labeling_protocol"]),
        slice_axes=tuple(resolve(name) for name in raw["slice_axes"]),
        description=raw.get("description", ""),
        representative=representative,
        authorization=authorization,
        cases=_load_cases(corpus_path, manifest_id),
    )


def assert_no_leakage(manifests: list[CorpusManifest]) -> None:
    """Refuse a manifest set whose splits share content.

    Checked across ALL loaded manifests at once rather than pairwise on load,
    because leakage is a property of the set: each corpus is individually fine
    and the overlap only exists between them.
    """
    by_hash: dict[str, list[tuple[str, str, str]]] = {}
    for manifest in manifests:
        for case in manifest.cases:
            by_hash.setdefault(case.content_hash(), []).append(
                (manifest.split, manifest.id, case.id)
            )

    overlaps = []
    for content_hash, occurrences in sorted(by_hash.items()):
        splits = {split for split, _, _ in occurrences}
        if len(splits) > 1:
            where = ", ".join(f"{split}:{mid}:{cid}" for split, mid, cid in sorted(occurrences))
            overlaps.append(f"  {content_hash[:12]}… appears in {sorted(splits)} — {where}")

    if overlaps:
        raise LeakageError(
            "train/calibration/test leakage: the same case content appears in "
            "more than one split, which inflates every downstream metric by an "
            "amount nobody can see.\n" + "\n".join(overlaps)
        )
