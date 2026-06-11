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
from app.policy.stage2_onnx import ClassifierSpec, OnnxClassifierStage2, OrtBackend
from app.policy.types import Direction, PolicyInput
from app.provisioning import provision_artifact

logger = logging.getLogger("platform.policy.stage2_provision")

_MINIMAL_POLICY = compile_policy(
    policy_row={"id": "_classify", "org_id": "_", "enforcement_level": "balanced"}
)

# Labels that mean "not a violation" — never treated as a detection category,
# so a benign input scored confidently safe doesn't fire.
_BENIGN_LABELS = frozenset({"safe", "benign", "clean", "negative", "ok"})
# Fallback category if a label map yields no positive labels.
_DEFAULT_CATEGORIES = ("prompt_injection",)


def _parse_label_map(raw: str) -> dict[int, str]:
    """Parse ``"0:safe,1:prompt_injection"`` → ``{0: "safe", 1: "prompt_injection"}``.

    Maps the model's raw class indices onto the platform's category taxonomy, so
    a binary SAFE/INJECTION classifier surfaces as ``prompt_injection`` even when
    the HuggingFace ``id2label`` didn't survive the ONNX export (it commonly
    doesn't — exported models then emit bare ``"0"``/``"1"`` labels).
    """
    mapping: dict[int, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        idx, _, label = pair.partition(":")
        try:
            mapping[int(idx.strip())] = label.strip()
        except ValueError:
            continue
    return mapping


def _positive_categories(id2label: dict[int, str]) -> tuple[str, ...]:
    """The detection categories — every mapped label that isn't benign."""
    return tuple(v for v in id2label.values() if v and v.lower() not in _BENIGN_LABELS)


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

    id2label = _parse_label_map(getattr(s, "stage2_onnx_label_map", "0:safe,1:prompt_injection"))
    categories = _positive_categories(id2label) or _DEFAULT_CATEGORIES
    threshold = float(getattr(s, "stage2_onnx_threshold", 0.5))
    spec = ClassifierSpec(
        id="stage2-onnx",
        name="prompt-injection-onnx",
        model_artifact_path=str(model_path),
        tokenizer_artifact_path=tokenizer_path,
        categories_detected=categories,
        threshold_per_label=dict.fromkeys(categories, threshold),
    )

    # Default backend: the real ORT backend, told how to relabel raw class
    # indices into our taxonomy (a test passes its own fake instead).
    if backend_factory is None:

        def backend_factory(spec: ClassifierSpec) -> OrtBackend:
            return OrtBackend(model_path=spec.model_artifact_path, id2label=id2label)

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
