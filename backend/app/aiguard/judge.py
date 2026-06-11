"""Stage-3 LLM judge service (Phase 1B) — a real, hosted second opinion.

Wires a small hosted model (default Claude Haiku) as the Stage-3 judge for
uncertain content, behind the same structured-prompt / JSON-schema contract
the deterministic engine uses. Two honesty + cost guarantees:

* **Disabled when unconfigured.** If ``judge_api_key_ref`` doesn't resolve
  (no key), the judge reports ``mode="disabled"`` and computes nothing — it
  never fabricates a verdict (Phase 0.5).
* **Cached by content hash.** Identical inputs reuse a verdict (Redis, 1h TTL)
  so repeated/replayed content doesn't re-bill the model. Best-effort: a Redis
  hiccup falls back to a live call, never an error.

The verdict shape (``is_violation``/``confidence``/``category``/``reason``) is
exactly what the Go runtime agent's HTTPStage3 expects, so its
``STAGE3_JUDGE_ENDPOINT`` can point straight at ``/v1/aiguard/judge``.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

from app.connectors.anthropic_connector import AnthropicConnector
from app.core.config import get_settings
from app.policy.stage3_judge import JudgeFn, make_connector_judge
from app.policy.types import Direction, PolicyInput
from app.security.secrets import SecretResolutionError, get_resolver
from app.services.redis_client import get_redis

logger = logging.getLogger("platform.aiguard.judge")

_CACHE_PREFIX = "judge:verdict:"
_CACHE_TTL_SECONDS = 3600

_DISABLED = {
    "is_violation": False,
    "confidence": 0.0,
    "category": "",
    "reason": "stage3 disabled: no judge configured",
    "mode": "disabled",
}


def build_judge_fn() -> JudgeFn | None:
    """Build the hosted JudgeFn from settings, or None when no key resolves.

    Resolving the reference (``env:`` / ``vault:``) confirms a key is present
    without making a network call; the connector resolves it lazily per request.
    """
    settings = get_settings()
    try:
        get_resolver().resolve(settings.judge_api_key_ref)
    except SecretResolutionError:
        return None
    connector = AnthropicConnector(
        api_key_ref=settings.judge_api_key_ref, model=settings.judge_model
    )
    return make_connector_judge(connector, max_tokens=settings.judge_max_tokens)


# ─────────────────────────────────────────────── process-wide judge

_judge_fn: Optional[JudgeFn] = None
_resolved = False


def get_judge_fn() -> JudgeFn | None:
    global _judge_fn, _resolved
    if not _resolved:
        _judge_fn = build_judge_fn()
        _resolved = True
    return _judge_fn


def set_judge_fn(fn: JudgeFn | None) -> None:
    """Install a judge fn explicitly (tests, or a custom connector)."""
    global _judge_fn, _resolved
    _judge_fn, _resolved = fn, True


def reset_for_tests() -> None:
    global _judge_fn, _resolved
    _judge_fn, _resolved = None, False


async def judge_content(text: str) -> dict[str, Any]:
    """Return a verdict dict for ``text``. ``mode`` is ``"disabled"`` (no judge),
    ``"stage3_llm_judge"`` (computed), or the cached verdict re-served."""
    fn = get_judge_fn()
    if fn is None:
        return dict(_DISABLED)

    key = _CACHE_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        redis = await get_redis()
        cached = await redis.get(key)
        if cached:
            return {**json.loads(cached), "mode": "stage3_llm_judge", "cached": True}
    except Exception as exc:  # noqa: BLE001 - cache is best-effort
        logger.debug("judge_cache_read_failed", extra={"error": str(exc)})
        redis = None

    verdict = await fn(PolicyInput(text=text, direction=Direction.INBOUND))
    out = {
        "is_violation": verdict.is_violation,
        "confidence": round(verdict.confidence, 4),
        "category": verdict.category,
        "reason": verdict.reason,
    }
    try:
        if redis is not None:
            await redis.set(key, json.dumps(out), ex=_CACHE_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001
        logger.debug("judge_cache_write_failed", extra={"error": str(exc)})
    return {**out, "mode": "stage3_llm_judge"}
