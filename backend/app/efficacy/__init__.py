"""Detection efficacy harness (P15a).

The harness an independent party could run. What it deliberately is NOT:

* It is not representative data. Every corpus shipped here is synthetic and
  says so in its manifest, in the JSON report, and in a banner at the top of
  the receipt.
* It is not an independent evaluation. Running your own harness against your
  own corpora and publishing the result is a demonstration, not evidence.

EXT-EFFICACY stays open. This closes the engineering half of it.
"""

from app.efficacy.manifest import (
    CorpusCase,
    CorpusManifest,
    LeakageError,
    ManifestError,
    assert_no_leakage,
    load_manifest,
)
from app.efficacy.metrics import ConfusionCounts, SliceMetrics, score, wilson_interval
from app.efficacy.report import build_report, render_receipt, write_report
from app.efficacy.runner import SYNTHETIC_LABEL, RunResult, run
from app.efficacy.slices import ALL_SLICES, NoAuthorizedCorpusError, SliceAxis, resolve

__all__ = [
    "ALL_SLICES",
    "SYNTHETIC_LABEL",
    "ConfusionCounts",
    "CorpusCase",
    "CorpusManifest",
    "LeakageError",
    "ManifestError",
    "NoAuthorizedCorpusError",
    "RunResult",
    "SliceAxis",
    "SliceMetrics",
    "assert_no_leakage",
    "build_report",
    "load_manifest",
    "render_receipt",
    "resolve",
    "run",
    "score",
    "wilson_interval",
    "write_report",
]
