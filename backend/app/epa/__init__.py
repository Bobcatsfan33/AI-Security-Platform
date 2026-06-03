"""Event Processing Agent (EPA) fleet — the streaming detection layer.

Each AgentEPA holds a continuously-updated BehavioralEnvelope for one agent
instance and emits EpaSignals on deviation. The EpaFleet supervises a fleet of
them off the streaming spine. This is the RAPIDE "stateful, autonomous
monitoring" capability (brief §3.4) — the streaming successor to the batch
anomaly detector.
"""

from app.epa.agent_epa import AgentEPA, EpaSignal, absence_signal
from app.epa.cross_agent import (
    CorrelationState,
    CorrelationStore,
    CrossAgentEPA,
    InMemoryCorrelationStore,
    RedisCorrelationStore,
)
from app.epa.envelope import BehavioralEnvelope
from app.epa.fleet import EpaFleet

# NOTE: EpaConsumerService is intentionally NOT eagerly imported here. It pulls
# in app.narratives, which imports app.epa.agent_epa — eager import would create
# an app.epa ↔ app.narratives cycle. Import it directly:
#   from app.epa.service import EpaConsumerService
from app.epa.store import (
    EnvelopeStore,
    InMemoryEnvelopeStore,
    RedisEnvelopeStore,
)

__all__ = [
    "AgentEPA",
    "EpaSignal",
    "absence_signal",
    "BehavioralEnvelope",
    "EpaFleet",
    "CrossAgentEPA",
    "CorrelationState",
    "CorrelationStore",
    "InMemoryCorrelationStore",
    "RedisCorrelationStore",
    "EnvelopeStore",
    "InMemoryEnvelopeStore",
    "RedisEnvelopeStore",
]
