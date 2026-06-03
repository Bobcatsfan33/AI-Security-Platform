"""Validation harness — purple-team replay through the real detection stack.

Runs each scenario's synthetic flow through an actual EpaFleet (per-agent EPAs)
+ CrossAgentEPA (correlation layer) and checks the expected detections fire.
Aggregates detection rate (true positives) and false-positive rate vs the
benign control — the measured efficacy the brief only asserts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.epa.agent_epa import EpaSignal
from app.epa.cross_agent import CrossAgentEPA, InMemoryCorrelationStore
from app.epa.fleet import EpaFleet
from app.epa.store import InMemoryEnvelopeStore
from app.validation.scenarios import ValidationScenario, all_scenarios


@dataclass
class ValidationResult:
    name: str
    brief_section: str
    is_attack: bool
    expected_kinds: set[str]
    detected_kinds: set[str]
    signals: list[EpaSignal] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        if self.is_attack:
            # Every expected detection must have fired.
            return self.expected_kinds.issubset(self.detected_kinds)
        # Benign: no detection at all.
        return not self.detected_kinds


@dataclass
class SuiteResult:
    results: list[ValidationResult]

    @property
    def attacks(self) -> list[ValidationResult]:
        return [r for r in self.results if r.is_attack]

    @property
    def benign(self) -> list[ValidationResult]:
        return [r for r in self.results if not r.is_attack]

    @property
    def detection_rate(self) -> float:
        atk = self.attacks
        return sum(1 for r in atk if r.passed) / len(atk) if atk else 0.0

    @property
    def false_positive_rate(self) -> float:
        ben = self.benign
        return sum(1 for r in ben if r.detected_kinds) / len(ben) if ben else 0.0

    def summary(self) -> dict:
        return {
            "scenarios": len(self.results),
            "attacks": len(self.attacks),
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "results": [
                {
                    "name": r.name,
                    "brief_section": r.brief_section,
                    "is_attack": r.is_attack,
                    "expected": sorted(r.expected_kinds),
                    "detected": sorted(r.detected_kinds),
                    "passed": r.passed,
                }
                for r in self.results
            ],
        }


async def run_scenario(scenario: ValidationScenario) -> ValidationResult:
    collected: list[EpaSignal] = []

    async def sink(sig: EpaSignal) -> None:
        collected.append(sig)

    # A fresh fleet per scenario so envelopes/flows don't leak across runs.
    fleet = EpaFleet(
        store=InMemoryEnvelopeStore(),
        sink=sink,
        cross_agent=CrossAgentEPA(InMemoryCorrelationStore()),
    )
    for event in scenario.events:
        await fleet.handle_event(event)

    detected = {s.kind for s in collected}
    return ValidationResult(
        name=scenario.name,
        brief_section=scenario.brief_section,
        is_attack=scenario.is_attack,
        expected_kinds=scenario.expected_kinds,
        detected_kinds=detected,
        signals=collected,
    )


async def run_suite() -> SuiteResult:
    results = [await run_scenario(s) for s in all_scenarios()]
    return SuiteResult(results=results)
