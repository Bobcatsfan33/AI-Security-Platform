"""Detector registry — the full AI Guard detector catalogue."""

from __future__ import annotations

from app.detectors.base import Detector
from app.detectors.advice import FinancialAdviceDetector, LegalAdviceDetector
from app.detectors.code_lang import (
    LanguageDetector,
    ProgrammingLanguageDetector,
    SourceCodeDetector,
)
from app.detectors.injection import (
    InvisibleTextDetector,
    JailbreakDetector,
    PromptInjectionDetector,
)
from app.detectors.sensitive import (
    BrandReputationDetector,
    CompetitionDetector,
    ContextAwarePIIDetector,
    SecretsDetector,
)
from app.detectors.text_safety import (
    GibberishDetector,
    LLMRefusalDetector,
    OffTopicDetector,
    ToxicityDetector,
)
from app.detectors.urls import MaliciousURLDetector, UnreachableURLDetector

ALL_DETECTORS: tuple[Detector, ...] = (
    PromptInjectionDetector(),
    JailbreakDetector(),
    InvisibleTextDetector(),
    ToxicityDetector(),
    MaliciousURLDetector(),
    UnreachableURLDetector(),
    OffTopicDetector(),
    GibberishDetector(),
    LegalAdviceDetector(),
    FinancialAdviceDetector(),
    LanguageDetector(),
    ProgrammingLanguageDetector(),
    SourceCodeDetector(),
    LLMRefusalDetector(),
    ContextAwarePIIDetector(),
    SecretsDetector(),
    BrandReputationDetector(),
    CompetitionDetector(),
)

_BY_NAME = {d.name: d for d in ALL_DETECTORS}


def get(name: str) -> Detector | None:
    return _BY_NAME.get(name)


def names() -> tuple[str, ...]:
    return tuple(_BY_NAME)


def default_thresholds() -> dict[str, float]:
    return {d.name: d.default_threshold for d in ALL_DETECTORS}
