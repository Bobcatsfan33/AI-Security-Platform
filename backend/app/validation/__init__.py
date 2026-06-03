"""Detection-efficacy validation — purple-team replay of multi-agent attacks.

Generates synthetic attack flows for the brief's headline scenarios (§4.1-4.4),
replays them through the real EPA stack, and measures detection rate + false-
positive rate vs a benign control. This turns the brief's asserted efficacy
into a measured, repeatable regression.
"""

from app.validation.harness import (
    SuiteResult,
    ValidationResult,
    run_scenario,
    run_suite,
)
from app.validation.scenarios import ValidationScenario, all_scenarios

__all__ = [
    "SuiteResult",
    "ValidationResult",
    "run_scenario",
    "run_suite",
    "ValidationScenario",
    "all_scenarios",
]
