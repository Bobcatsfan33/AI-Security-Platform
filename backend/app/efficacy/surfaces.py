"""The detection surfaces under evaluation.

"Efficacy" for this product is not one number from one model. Two independent
paths make detections, and only measuring the first is how a suite comes to
report excellent efficacy for a system whose behavioural half was never
exercised:

* ``prompt_injection`` — content inspection (AI Guard detectors, including the
  decode/normalize pre-pass and, when provisioned, the ONNX Stage-2 classifier).
* ``behavioural`` — the attack-graph / anomaly path: per-agent EPAs and the
  cross-agent correlation layer, which fire on event SEQUENCES rather than on
  any single message.

Each surface reports whether it flagged a case and how long that took, plus a
hash binding of exactly what was evaluated so the report cannot be confused
with a run of some other configuration.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol

from app.efficacy.manifest import CorpusCase


@dataclass(frozen=True)
class Verdict:
    flagged: bool
    latency_ms: float
    detail: str = ""


class Surface(Protocol):
    """One evaluated detection path."""

    name: str

    def handles(self, case: CorpusCase) -> bool: ...

    def evaluate(self, case: CorpusCase) -> Verdict: ...

    def binding(self) -> dict[str, str]:
        """Hashes identifying exactly what was evaluated.

        Without this a report says "recall 0.91" about an unnamed
        configuration; six weeks later nobody can tell whether it described the
        heuristic fallback or a real model.
        """
        ...


def _hash_obj(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PromptInjectionSurface:
    """Content detection through the real AI Guard service."""

    name = "prompt_injection"

    def __init__(self, config: dict[str, dict[str, Any]] | None = None) -> None:
        from app.aiguard.service import AIGuardService

        self._service = AIGuardService()
        self._config = config or {}

    def handles(self, case: CorpusCase) -> bool:
        return case.kind == "text"

    def evaluate(self, case: CorpusCase) -> Verdict:
        from app.detectors.base import DetectorContext, Direction

        text = case.payload.get("text", "")
        # content_trust rides in `extra`, matching app/benchmark/scorecard.py.
        # It is what distinguishes a user typing an instruction from an
        # instruction arriving inside retrieved content, which is the whole
        # indirect-injection slice.
        trust = case.payload.get("content_trust", "direct")
        context = DetectorContext(direction=Direction.INBOUND, extra={"content_trust": trust})

        started = time.perf_counter()
        response = self._service.inspect(
            text=text,
            direction=Direction.INBOUND,
            config=self._config,
            context=context,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        # "Flagged" is any non-allow action. Treating only `block` as a
        # detection would score the flag-for-review path as a miss, which is
        # not how the product is operated.
        flagged = getattr(response, "action", "allow") != "allow"
        return Verdict(
            flagged=flagged, latency_ms=elapsed_ms, detail=str(getattr(response, "action", ""))
        )

    def binding(self) -> dict[str, str]:
        from app.detectors.registry import ALL_DETECTORS

        return {
            "surface": self.name,
            "detector_set_sha256": _hash_obj(sorted(d.name for d in ALL_DETECTORS)),
            "detector_config_sha256": _hash_obj(self._config),
            "stage2_mode": _stage2_mode(),
        }


def _stage2_mode() -> str:
    """Whether a verified ONNX model or the heuristic answered.

    Recorded because the same corpus scores very differently under each, and a
    report that does not say which one ran is not reproducible.
    """
    try:
        from app.policy.stage2_provision import build_onnx_stage2_from_settings

        return (
            "stage2_onnx" if build_onnx_stage2_from_settings() is not None else "stage2_heuristic"
        )
    except Exception:
        return "stage2_heuristic"


class BehaviouralSurface:
    """The attack-graph / anomaly path: per-agent EPAs + cross-agent correlation.

    A fresh fleet per case, deliberately. These detectors are stateful — an
    envelope carries history — so reusing one fleet would let case N's
    behaviour decide case N+1's verdict, and the score would depend on corpus
    order rather than on the detector.
    """

    name = "behavioural"

    def handles(self, case: CorpusCase) -> bool:
        return case.kind == "event_sequence"

    def evaluate(self, case: CorpusCase) -> Verdict:
        import asyncio

        events = case.payload.get("events", [])
        started = time.perf_counter()
        signals = asyncio.run(self._run(events))
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        kinds = sorted({getattr(s, "kind", "") for s in signals})
        return Verdict(flagged=bool(signals), latency_ms=elapsed_ms, detail=",".join(kinds))

    async def _run(self, events: list[dict[str, Any]]) -> list[Any]:
        from app.epa.cross_agent import CrossAgentEPA, InMemoryCorrelationStore
        from app.epa.fleet import EpaFleet
        from app.epa.store import InMemoryEnvelopeStore

        fleet = EpaFleet(
            store=InMemoryEnvelopeStore(),
            cross_agent=CrossAgentEPA(store=InMemoryCorrelationStore()),
        )
        signals: list[Any] = []
        for event in events:
            signals.extend(await fleet.handle_event(event))
        return signals

    def binding(self) -> dict[str, str]:
        """Bind the signal taxonomy and the cold-start threshold.

        Both change what this surface can possibly detect. MATURITY_MIN in
        particular decides whether an envelope is allowed to alert at all, so a
        corpus whose sequences are shorter than it will score zero for reasons
        that have nothing to do with detection quality — a reader needs the
        number to interpret the result.
        """
        import typing

        from app.epa import agent_epa
        from app.epa.envelope import MATURITY_MIN

        return {
            "surface": self.name,
            "signal_kinds_sha256": _hash_obj(sorted(typing.get_args(agent_epa.SignalKind))),
            "maturity_min": str(MATURITY_MIN),
        }


def default_surfaces() -> tuple[Surface, ...]:
    return (PromptInjectionSurface(), BehaviouralSurface())
