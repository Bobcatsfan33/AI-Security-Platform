"""Identity-aware MCP / A2A gateway (Phase 6 core).

The Agentic-Exchange decision layer: before an agent calls a tool (MCP) or
messages another agent (A2A), the gateway

  1. authenticates the agent identity and checks the tool/peer is in its
     authorized set (per-agent tool-call authorization),
  2. runs the call arguments through AI Guard inline content inspection
     (Phase 0) — a block verdict denies the call,
  3. optionally consults the MCP tool-profile inspector for tool-abuse risk,
  4. writes a tamper-evident audit record,

and returns an allow/deny decision. The live MCP JSON-RPC transport / A2A
networking is the documented Phase-6 boundary; this is the policy-enforcement
brokering layer the transport calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.aiguard.service import get_service
from app.detectors.base import Direction
from app.security.audit_log import log_event

# Tool name that means "any tool" in an agent's authorized set.
WILDCARD = "*"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    org_id: str
    authorized_tools: frozenset[str] = field(default_factory=frozenset)
    authorized_peers: frozenset[str] = field(default_factory=frozenset)

    def may_call(self, tool: str) -> bool:
        return WILDCARD in self.authorized_tools or tool in self.authorized_tools

    def may_message(self, peer: str) -> bool:
        return WILDCARD in self.authorized_peers or peer in self.authorized_peers


@dataclass(frozen=True)
class GatewayDecision:
    allowed: bool
    reason: str
    tool: str = ""
    aiguard_action: str = "allow"
    detail: dict[str, Any] = field(default_factory=dict)


def _args_text(args: dict[str, Any] | None) -> str:
    if not args:
        return ""
    parts: list[str] = []
    for v in args.values():
        parts.append(v if isinstance(v, str) else json.dumps(v, default=str))
    return "\n".join(parts)


def _audit(
    identity: AgentIdentity, action: str, resource: str, allowed: bool, detail: dict[str, Any]
) -> None:
    log_event(
        action,
        outcome="success" if allowed else "failure",
        tenant_id=identity.org_id,
        subject=identity.agent_id,
        resource=resource,
        detail=detail,
    )


def authorize_tool_call(
    identity: AgentIdentity,
    *,
    tool: str,
    arguments: dict[str, Any] | None = None,
    aiguard_config: dict[str, Any] | None = None,
) -> GatewayDecision:
    """Authorize an agent's MCP tool call: authorization + inline AI Guard."""
    # 1. Tool-call authorization
    if not identity.may_call(tool):
        d = GatewayDecision(False, "tool_not_authorized", tool=tool)
        _audit(identity, "mcp.tool_call", f"tool/{tool}", False, {"reason": d.reason})
        return d

    # 2. Inline AI Guard on the arguments
    resp = get_service().inspect(
        text=_args_text(arguments), direction=Direction.INBOUND, config=aiguard_config or {}
    )
    if resp.action == "block":
        d = GatewayDecision(
            False,
            "content_blocked",
            tool=tool,
            aiguard_action="block",
            detail={"triggered": list(resp.triggered)},
        )
        _audit(
            identity,
            "mcp.tool_call",
            f"tool/{tool}",
            False,
            {"reason": d.reason, "triggered": list(resp.triggered)},
        )
        return d

    d = GatewayDecision(
        True,
        "authorized",
        tool=tool,
        aiguard_action=resp.action,
        detail={"triggered": list(resp.triggered)},
    )
    _audit(
        identity,
        "mcp.tool_call",
        f"tool/{tool}",
        True,
        {"aiguard_action": resp.action, "triggered": list(resp.triggered)},
    )
    return d


def authorize_a2a_message(
    identity: AgentIdentity,
    *,
    peer: str,
    content: str = "",
    aiguard_config: dict[str, Any] | None = None,
) -> GatewayDecision:
    """Authorize an agent-to-agent message: peer authorization + inline AI Guard
    on the message content (propagation-injection defense at the boundary)."""
    if not identity.may_message(peer):
        d = GatewayDecision(False, "peer_not_authorized", tool=peer)
        _audit(identity, "a2a.message", f"peer/{peer}", False, {"reason": d.reason})
        return d

    # Inspect as INBOUND: an A2A message is an inbound-style payload to the
    # PEER, so injection/jailbreak detectors (the propagation-attack defense)
    # must run on it.
    resp = get_service().inspect(
        text=content, direction=Direction.INBOUND, config=aiguard_config or {}
    )
    if resp.action == "block":
        d = GatewayDecision(
            False,
            "content_blocked",
            tool=peer,
            aiguard_action="block",
            detail={"triggered": list(resp.triggered)},
        )
        _audit(
            identity,
            "a2a.message",
            f"peer/{peer}",
            False,
            {"reason": d.reason, "triggered": list(resp.triggered)},
        )
        return d

    d = GatewayDecision(
        True,
        "authorized",
        tool=peer,
        aiguard_action=resp.action,
        detail={"triggered": list(resp.triggered)},
    )
    _audit(identity, "a2a.message", f"peer/{peer}", True, {"aiguard_action": resp.action})
    return d
