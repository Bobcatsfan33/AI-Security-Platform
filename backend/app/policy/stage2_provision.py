"""Stage-2 ONNX provisioning + classify service (Phase 1A).

Wires a checksum-pinned ONNX model into a runnable Stage-2 classifier:
provision the model + tokenizer artifacts (download + verify-sha256 + cache),
build :class:`OnnxClassifierStage2` over them, and expose a single
``classify_text`` that returns the ``{matched, confidence, category}`` shape the
runtime agent's Stage-2 sidecar contract uses.

Honest fallback: when no model URL is configured (or provisioning fails), the
deterministic :class:`HeuristicStage2` runs instead and the result is labelled
``stage2_heuristic`` — the platform never claims an ML verdict it didn't compute.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.policy.compiled import compile_policy
from app.policy.stage2_heuristic import HeuristicStage2
from app.policy.stage2_onnx import ClassifierSpec, OnnxClassifierStage2
from app.policy.types import Direction, PolicyInput
from app.provisioning import provision_artifact

logger = logging.getLogger("platform.policy.stage2_provision")

_MINIMAL_POLICY = compile_policy(
    policy_row={"id": "_classify", "org_id": "_", "enforcement_level": "balanced"}
)

# Categories the prompt-injection classifier emits, with default trigger
# thresholds. (Operators tune per-deployment; these are sane defaults.)
_DEFAULT_CATEGORIES = ("prompt_injection", "jailbreak")
_DEFAULT_THRESHOLDS = {"prompt_injection": 0.5, "jailbreak": 0.5}


def build_onnx_stage2_from_settings(
    *, backend_factory: Any = None, tokenizer_factory: Any = None
) -> OnnxClassifierStage2 | None:
    """Provision the configured model+tokenizer and build the ONNX Stage 2.

    Returns ``None`` when no model URL is configured or provisioning fails — the
    caller falls back to the heuristic. ``*_factory`` overrides are for tests
    (inject a fake backend/tokenizer instead of loading a real model).
    """
    s = get_settings()
    if not s.stage2_onnx_model_url:
        return None

    cache = Path(s.model_cache_dir)
    try:
        model_path = provision_artifact(
            url=s.stage2_onnx_model_url,
            sha256=s.stage2_onnx_model_sha256,
            dest=cache / "stage2_model.onnx",
        )
        tokenizer_path: str | None = None
        if s.stage2_onnx_tokenizer_url:
            tokenizer_path = str(
                provision_artifact(
                    url=s.stage2_onnx_tokenizer_url,
                    sha256=s.stage2_onnx_tokenizer_sha256,
                    dest=cache / "stage2_tokenizer.json",
                )
            )
    except Exception as exc:  # fail open to the heuristic Stage 2
        logger.warning("stage2_model_provision_failed", extra={"error": str(exc)})
        return None

    spec = ClassifierSpec(
        id="stage2-onnx",
        name="prompt-injection-onnx",
        model_artifact_path=str(model_path),
        tokenizer_artifact_path=tokenizer_path,
        categories_detected=_DEFAULT_CATEGORIES,
        threshold_per_label=_DEFAULT_THRESHOLDS,
    )
    return OnnxClassifierStage2(
        specs=[spec], backend_factory=backend_factory, tokenizer_factory=tokenizer_factory
    )


# ─────────────────────────────────────────────── process-wide stage

_stage: Any = None
_resolved = False


def get_stage2() -> Any:
    """The provisioned ONNX stage (cached), or the heuristic when unconfigured."""
    global _stage, _resolved
    if not _resolved:
        _stage = build_onnx_stage2_from_settings() or HeuristicStage2()
        _resolved = True
    return _stage


def set_stage2(stage: Any) -> None:
    global _stage, _resolved
    _stage, _resolved = stage, True


def reset_for_tests() -> None:
    global _stage, _resolved
    _stage, _resolved = None, False


async def classify_text(text: str) -> dict[str, Any]:
    """Classify one input through the provisioned ONNX model (or the heuristic
    fallback). Returns ``{matched, confidence, category, mode}`` — the runtime
    agent's Stage-2 contract plus the honest compute-mode label."""
    stage = get_stage2()
    result = await stage.classify(
        input_=PolicyInput(text=text, direction=Direction.INBOUND), policy=_MINIMAL_POLICY
    )
    return {
        "matched": result.matched,
        "confidence": round(result.confidence, 4),
        "category": result.category,
        "mode": result.mode or "stage2_heuristic",
    }
