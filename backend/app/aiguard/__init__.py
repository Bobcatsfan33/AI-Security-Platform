"""AI Guard — inline runtime protection surface."""

from app.aiguard.bridge import aiguard_response_to_signal
from app.aiguard.publish import (
    NarrativeSignalPublisher,
    SignalPublisher,
    maybe_publish_inspection,
)
from app.aiguard.response import AIGuardResponse, DetectorOutcome
from app.aiguard.service import AIGuardService, get_service

__all__ = [
    "AIGuardResponse",
    "AIGuardService",
    "DetectorOutcome",
    "NarrativeSignalPublisher",
    "SignalPublisher",
    "aiguard_response_to_signal",
    "get_service",
    "maybe_publish_inspection",
]
