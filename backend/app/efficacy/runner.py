"""Run a corpus set through the detection surfaces and report per-slice metrics.

Two properties shape the design.

**Deterministic.** Cases are evaluated in sorted order and nothing samples,
shuffles, or times out into a different path. Two runs over the same corpora
and the same code produce the same verdicts, so a changed number means changed
behaviour rather than changed luck.

**Resumable.** Verdicts are appended to a JSONL checkpoint as they are produced,
and a resumed run replays completed case ids instead of re-evaluating them.
Evaluation is the expensive part; losing an hour of it to an interrupted
process is how people start quietly running smaller corpora.

The report binds the corpus hashes, the surface hashes, and the code revision
together. A number that cannot say what produced it is not evidence.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.efficacy.manifest import CorpusManifest, assert_no_leakage
from app.efficacy.metrics import SliceMetrics, score
from app.efficacy.slices import ALL_SLICES, NoAuthorizedCorpusError, SliceAxis
from app.efficacy.surfaces import Surface, default_surfaces

# The label every result carries until an authorized representative corpus
# exists. Deliberately blunt: a reader skimming the JSON should not be able to
# mistake this for a measurement of real traffic.
SYNTHETIC_LABEL = "synthetic-demonstration"
AUTHORIZED_LABEL = "authorized-corpus"


@dataclass(frozen=True)
class CaseVerdict:
    case_id: str
    manifest_id: str
    surface: str
    is_attack: bool
    flagged: bool
    latency_ms: float
    slices: tuple[str, ...]
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "manifest_id": self.manifest_id,
            "surface": self.surface,
            "is_attack": self.is_attack,
            "flagged": self.flagged,
            "latency_ms": round(self.latency_ms, 4),
            "slices": list(self.slices),
            "detail": self.detail,
        }

    @staticmethod
    def from_dict(record: dict[str, Any]) -> CaseVerdict:
        return CaseVerdict(
            case_id=record["case_id"],
            manifest_id=record["manifest_id"],
            surface=record["surface"],
            is_attack=record["is_attack"],
            flagged=record["flagged"],
            latency_ms=record["latency_ms"],
            slices=tuple(record.get("slices", ())),
            detail=record.get("detail", ""),
        )


@dataclass
class RunResult:
    verdicts: list[CaseVerdict] = field(default_factory=list)
    overall: dict[str, SliceMetrics] = field(default_factory=dict)
    per_slice: dict[str, dict[str, SliceMetrics]] = field(default_factory=dict)
    unevaluated_slices: dict[str, str] = field(default_factory=dict)
    bindings: dict[str, Any] = field(default_factory=dict)
    resumed: int = 0

    @property
    def evidence_class(self) -> str:
        """Synthetic unless every contributing corpus is authorized.

        Computed from the manifests rather than passed in, so it cannot be
        overridden by a caller who would prefer a stronger label.
        """
        corpora = self.bindings.get("corpora", [])
        if corpora and all(entry.get("representative") for entry in corpora):
            return AUTHORIZED_LABEL
        return SYNTHETIC_LABEL


def _git_revision() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def _load_checkpoint(path: pathlib.Path) -> dict[tuple[str, str], CaseVerdict]:
    """Replay a previous run's verdicts, keyed by (case id, surface).

    A truncated final line is dropped rather than fatal: an interrupted run is
    the normal reason a checkpoint exists, and refusing to resume from one
    would defeat the point.
    """
    if not path.is_file():
        return {}
    done: dict[tuple[str, str], CaseVerdict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        verdict = CaseVerdict.from_dict(record)
        done[(verdict.case_id, verdict.surface)] = verdict
    return done


def run(
    manifests: list[CorpusManifest],
    *,
    surfaces: tuple[Surface, ...] | None = None,
    checkpoint: pathlib.Path | None = None,
    requested_slices: tuple[SliceAxis, ...] = ALL_SLICES,
) -> RunResult:
    """Evaluate every case in every manifest against every surface that handles it."""
    surfaces = surfaces or default_surfaces()

    # Leakage first. Every metric below is wrong if the splits overlap, so
    # there is no point computing them and reporting the problem afterwards.
    assert_no_leakage(manifests)

    result = RunResult()
    result.bindings = {
        "git_revision": _git_revision(),
        "corpora": [
            {
                "id": m.id,
                "sha256": m.sha256,
                "split": m.split,
                "cases": len(m.cases),
                "representative": m.representative,
                "provenance": m.provenance,
                "labeling_protocol": m.labeling_protocol,
            }
            for m in sorted(manifests, key=lambda m: m.id)
        ],
        "surfaces": [s.binding() for s in surfaces],
    }

    # A requested slice that needs authorized data is recorded as UNEVALUATED
    # with its reason, never silently satisfied from synthetic corpora.
    authorized_ids = {m.id for m in manifests if m.representative}
    for axis in requested_slices:
        if axis.requires_authorized_corpus and not authorized_ids:
            result.unevaluated_slices[axis.name] = (
                "no authorized corpus: this slice cannot be satisfied by synthetic "
                "data, and no manifest declares representative=true with an "
                "authorization. EXT-EFFICACY remains open."
            )

    done = _load_checkpoint(checkpoint) if checkpoint else {}
    result.resumed = len(done)
    sink = None
    if checkpoint:
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        sink = checkpoint.open("a", encoding="utf-8")

    try:
        # Sorted by manifest then case id: the run order is a property of the
        # data, not of dict iteration or filesystem listing order.
        for manifest in sorted(manifests, key=lambda m: m.id):
            # Only the test split is scored. Training and calibration cases are
            # loaded so leakage can be detected against them, but scoring a
            # model on what tuned it is the mistake this harness exists to make
            # impossible.
            if manifest.split != "test":
                continue
            for case in sorted(manifest.cases, key=lambda c: c.id):
                for surface in surfaces:
                    if not surface.handles(case):
                        continue
                    key = (case.id, surface.name)
                    if key in done:
                        result.verdicts.append(done[key])
                        continue
                    verdict_raw = surface.evaluate(case)
                    verdict = CaseVerdict(
                        case_id=case.id,
                        manifest_id=manifest.id,
                        surface=surface.name,
                        is_attack=case.label == "attack",
                        flagged=verdict_raw.flagged,
                        latency_ms=verdict_raw.latency_ms,
                        slices=case.slices,
                        detail=verdict_raw.detail,
                    )
                    result.verdicts.append(verdict)
                    if sink:
                        sink.write(json.dumps(verdict.as_dict(), sort_keys=True) + "\n")
                        sink.flush()  # a crash must not lose the case just paid for
    finally:
        if sink:
            sink.close()

    _aggregate(result)
    return result


def _aggregate(result: RunResult) -> None:
    by_surface: dict[str, list[tuple[bool, bool, float]]] = defaultdict(list)
    by_surface_slice: dict[str, dict[str, list[tuple[bool, bool, float]]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for verdict in result.verdicts:
        outcome = (verdict.is_attack, verdict.flagged, verdict.latency_ms)
        by_surface[verdict.surface].append(outcome)
        for slice_name in verdict.slices:
            by_surface_slice[verdict.surface][slice_name].append(outcome)

    result.overall = {
        surface: score(f"{surface}:overall", outcomes) for surface, outcomes in by_surface.items()
    }
    result.per_slice = {
        surface: {
            slice_name: score(f"{surface}:{slice_name}", outcomes)
            for slice_name, outcomes in sorted(slices.items())
        }
        for surface, slices in by_surface_slice.items()
    }


def require_authorized_slice(axis: SliceAxis, manifests: list[CorpusManifest]) -> None:
    """Raise unless an authorized corpus backs this slice.

    The explicit form, for callers that want the refusal to be fatal rather
    than recorded as unevaluated.
    """
    if not axis.requires_authorized_corpus:
        return
    if not any(m.representative for m in manifests):
        raise NoAuthorizedCorpusError(
            f"slice {axis.name!r} requires an authorized representative corpus. "
            "No manifest declares representative=true with an authorization, and "
            "synthetic data must not be substituted."
        )
