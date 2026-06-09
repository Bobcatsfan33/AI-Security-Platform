"""Stage 2 ONNX classifier engine — Python-side.

The blueprint specifies Stage 2 (ML) as ONNX inference for prompt-
injection / data-leakage / jailbreak / output-safety detection. The
runtime agent (Sprint 7) will call this through a Rust+CGo bridge; the
Python implementation here is what the evaluation engine and policy
simulation endpoint use.

Design
------
The engine is split into three layers so we can swap any one without
touching the others:

  1. ``ClassifierBackend`` (Protocol) — runs raw inference on
     pre-tokenized input. Default impl: :class:`OrtBackend` using
     ``onnxruntime``.
  2. ``Tokenizer`` (Protocol) — converts text -> input_ids / attention_
     mask. Default impl: :class:`HfTokenizer` using ``tokenizers``.
  3. :class:`OnnxClassifierStage2` — orchestrates tokenize -> infer ->
     map outputs to a :class:`StageResult`.

Model registry
--------------
Classifier configs live in :class:`Policy.classifiers` (JSONB array).
Each entry has:

    {
        "id": "prompt-injection-v3",
        "name": "Prompt injection detector",
        "model_artifact_path": "file:///models/pi-v3.onnx",
        "tokenizer_artifact_path": "file:///models/pi-v3-tokenizer.json",
        "categories_detected": ["prompt_injection", "jailbreak"],
        "threshold_per_label": {"prompt_injection": 0.7, "jailbreak": 0.7},
        "max_input_length": 8192,
        "enabled": true
    }

For Sprint 3 the artifact paths must be ``file://`` URLs to local
files. Remote (s3://, https://) loading is a Sprint 3 follow-on.

No-op semantics
---------------
When no classifier is configured (or all configured classifiers are
disabled), the engine returns ``StageResult(matched=False)`` so the
pipeline orchestrator falls through to its no-match path. This means
the policy continues to work even if the operator hasn't set up Stage 2.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from app.policy.compiled import CompiledPolicy
from app.policy.types import PolicyInput, StageResult

logger = logging.getLogger("platform.policy.stage2")


# ─────────────────────────────────────────────── Protocols


@runtime_checkable
class ClassifierBackend(Protocol):
    """Runs ONNX inference. Stub for tests; OrtBackend in production."""

    def classify(self, *, input_ids: list[int], attention_mask: list[int]) -> dict[str, float]:
        """Return label -> probability for one input.

        Implementations decide how to map output tensors to labels —
        typically a softmax over logits with the model's id2label map.
        """
        ...


@runtime_checkable
class Tokenizer(Protocol):
    """Text -> (input_ids, attention_mask). Stub for tests; HF in prod."""

    def encode(self, text: str, *, max_length: int) -> tuple[list[int], list[int]]: ...


# ─────────────────────────────────────────────── Config


@dataclass(frozen=True)
class ClassifierSpec:
    """One classifier configuration. Built from a Policy.classifiers entry."""

    id: str
    name: str
    model_artifact_path: str
    tokenizer_artifact_path: str | None
    categories_detected: tuple[str, ...]
    threshold_per_label: dict[str, float]
    max_input_length: int = 8192
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ClassifierSpec:
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name", "")),
            model_artifact_path=str(d.get("model_artifact_path", "")),
            tokenizer_artifact_path=d.get("tokenizer_artifact_path"),
            categories_detected=tuple(d.get("categories_detected") or []),
            threshold_per_label=dict(d.get("threshold_per_label") or {}),
            max_input_length=int(d.get("max_input_length", 8192)),
            enabled=bool(d.get("enabled", True)),
        )


# ─────────────────────────────────────────────── Default backends


class OrtBackend:
    """ONNX Runtime backend — production default.

    Loads the model lazily on first ``classify`` call. The label mapping
    is read from the model's ``id2label`` metadata when present;
    otherwise the caller must supply it through the constructor.
    """

    def __init__(
        self,
        *,
        model_path: str,
        id2label: dict[int, str] | None = None,
        providers: list[str] | None = None,
    ) -> None:
        self._model_path = _resolve_artifact_path(model_path)
        self._explicit_id2label = id2label or {}
        self._providers = providers or ["CPUExecutionProvider"]
        self._session: Any = None
        self._id2label: dict[int, str] = {}

    def classify(self, *, input_ids: list[int], attention_mask: list[int]) -> dict[str, float]:
        session = self._get_session()
        import numpy as np  # local — onnxruntime pulls numpy

        feeds: dict[str, np.ndarray] = {}
        # We expect a standard transformer model with two inputs.
        # If only one is declared, drop attention_mask.
        declared = {inp.name for inp in session.get_inputs()}
        ids_arr = np.array([input_ids], dtype=np.int64)
        feeds["input_ids" if "input_ids" in declared else next(iter(declared))] = ids_arr
        if "attention_mask" in declared:
            feeds["attention_mask"] = np.array([attention_mask], dtype=np.int64)

        outputs = session.run(None, feeds)
        logits = outputs[0][0]  # (batch=1, num_labels) -> (num_labels,)
        probs = _softmax(list(logits))
        return {self._label_for(i): probs[i] for i in range(len(probs))}

    def _get_session(self) -> Any:
        if self._session is None:
            try:
                import onnxruntime as ort  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError("onnxruntime not installed") from exc
            self._session = ort.InferenceSession(self._model_path, providers=self._providers)
            self._id2label = self._extract_id2label(self._session)
        return self._session

    def _label_for(self, idx: int) -> str:
        if self._explicit_id2label:
            return self._explicit_id2label.get(idx, str(idx))
        if idx in self._id2label:
            return self._id2label[idx]
        return str(idx)

    @staticmethod
    def _extract_id2label(session: Any) -> dict[int, str]:
        """HuggingFace ONNX exports store id2label in metadata_props."""
        meta = session.get_modelmeta()
        custom = getattr(meta, "custom_metadata_map", {}) or {}
        raw = custom.get("id2label") or custom.get("hf_id2label")
        if not raw:
            return {}
        try:
            import json

            parsed = json.loads(raw)
            return {int(k): str(v) for k, v in parsed.items()}
        except (json.JSONDecodeError, ValueError, TypeError):
            return {}


class HfTokenizer:
    """HuggingFace tokenizers backend — production default."""

    def __init__(self, *, tokenizer_path: str) -> None:
        self._tokenizer_path = _resolve_artifact_path(tokenizer_path)
        self._tokenizer: Any = None

    def encode(self, text: str, *, max_length: int) -> tuple[list[int], list[int]]:
        tokenizer = self._load()
        encoded = tokenizer.encode(text)
        ids = encoded.ids[:max_length]
        mask = [1] * len(ids)
        return ids, mask

    def _load(self) -> Any:
        if self._tokenizer is None:
            try:
                from tokenizers import Tokenizer as HFTokenizer  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "tokenizers package not installed; required for HF tokenizer artifacts"
                ) from exc
            self._tokenizer = HFTokenizer.from_file(self._tokenizer_path)
        return self._tokenizer


# ─────────────────────────────────────────────── Engine


class OnnxClassifierStage2:
    """Stage 2 engine. Orchestrates tokenize -> infer -> emit StageResult.

    A pipeline typically holds ONE instance per policy. Each instance can
    drive one or more classifiers (e.g. prompt_injection + jailbreak +
    output_safety) — we walk the list and return the highest-confidence
    match. Stage 3 escalation routing happens upstream in the
    PolicyPipeline orchestrator, based on confidence thresholds in
    CompiledPolicy.
    """

    def __init__(
        self,
        *,
        specs: list[ClassifierSpec],
        backend_factory: Any | None = None,
        tokenizer_factory: Any | None = None,
    ) -> None:
        self._specs = [s for s in specs if s.enabled]
        self._backend_factory = backend_factory or _default_backend_factory
        self._tokenizer_factory = tokenizer_factory or _default_tokenizer_factory
        # Lazy: build (backend, tokenizer) per spec on first use
        self._cache: dict[str, tuple[ClassifierBackend, Tokenizer]] = {}

    async def classify(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult:
        if not self._specs:
            return StageResult(
                stage="stage2_ml", matched=False, action="allowed", mode="stage2_onnx"
            )

        start_ns = time.perf_counter_ns()
        best: tuple[str, str, float] | None = None  # (rule_id, category, confidence)

        for spec in self._specs:
            try:
                backend, tokenizer = self._get_or_build(spec)
            except Exception as exc:
                logger.warning(
                    "stage2_classifier_load_failed",
                    extra={"spec_id": spec.id, "error": str(exc)},
                )
                continue

            try:
                ids, mask = tokenizer.encode(input_.text, max_length=spec.max_input_length)
                label_probs = backend.classify(input_ids=ids, attention_mask=mask)
            except Exception as exc:
                logger.warning(
                    "stage2_classifier_infer_failed",
                    extra={"spec_id": spec.id, "error": str(exc)},
                )
                continue

            # Pick the highest-confidence label this classifier produced
            # whose probability exceeds its configured threshold.
            for label, prob in label_probs.items():
                if label not in spec.categories_detected:
                    continue
                threshold = spec.threshold_per_label.get(label, 0.5)
                if prob < threshold:
                    continue
                if best is None or prob > best[2]:
                    best = (spec.id, label, prob)

        latency_us = (time.perf_counter_ns() - start_ns) // 1000
        if best is None:
            return StageResult(
                stage="stage2_ml",
                matched=False,
                action="allowed",
                latency_us=int(latency_us),
                mode="stage2_onnx",
            )

        rule_id, category, confidence = best
        # The orchestrator handles routing on confidence — we just emit
        # "flagged" as the default action. Operators wanting blocked-on-
        # match should set enforcement_level=fast and add a Stage 1
        # regex; Stage 2 is intentionally heuristic.
        return StageResult(
            stage="stage2_ml",
            mode="stage2_onnx",
            matched=True,
            action="flagged",
            severity="medium",
            category=category,
            rule_id=rule_id,
            confidence=confidence,
            reason=f"classifier {rule_id!r} matched {category!r}",
            latency_us=int(latency_us),
            evidence={"label_probs": {category: round(confidence, 4)}},
        )

    def _get_or_build(self, spec: ClassifierSpec) -> tuple[ClassifierBackend, Tokenizer]:
        if spec.id not in self._cache:
            backend = self._backend_factory(spec)
            tokenizer = self._tokenizer_factory(spec)
            self._cache[spec.id] = (backend, tokenizer)
        return self._cache[spec.id]


# ─────────────────────────────────────────────── Factory helpers


def _default_backend_factory(spec: ClassifierSpec) -> ClassifierBackend:
    return OrtBackend(model_path=spec.model_artifact_path)


def _default_tokenizer_factory(spec: ClassifierSpec) -> Tokenizer:
    if not spec.tokenizer_artifact_path:
        raise RuntimeError(f"classifier {spec.id!r} has no tokenizer_artifact_path")
    return HfTokenizer(tokenizer_path=spec.tokenizer_artifact_path)


def specs_from_policy(policy: CompiledPolicy) -> list[ClassifierSpec]:
    """Extract ClassifierSpec list from a compiled policy's classifiers
    field. Used at pipeline construction to wire up Stage 2."""
    out: list[ClassifierSpec] = []
    # CompiledPolicy doesn't currently carry `classifiers` directly — it
    # was set aside during compile. Pull from the raw rule list when
    # callers attach it; if absent, return an empty list.
    raw = getattr(policy, "_classifiers", None)
    if not raw:
        return []
    for entry in raw:
        if isinstance(entry, dict):
            out.append(ClassifierSpec.from_dict(entry))
    return out


# ─────────────────────────────────────────────── Utilities


def _resolve_artifact_path(path: str) -> str:
    """Accept ``file://`` URLs and absolute / relative paths.

    Remote schemes (s3://, https://) are a follow-on; this function
    raises NotImplementedError so callers see the gap clearly rather
    than silently falling back to ``""``.
    """
    if path.startswith("file://"):
        return path[len("file://") :]
    if path.startswith(("s3://", "https://", "http://")):
        raise NotImplementedError(
            f"remote artifact path {path!r} not yet supported; "
            "Sprint 3 follow-on. Use file:// for now."
        )
    if not Path(path).is_absolute():
        # Treat as relative to CWD; production deployments should always
        # use absolute paths.
        return str(Path(path).resolve())
    return path


def _softmax(logits: list[float]) -> list[float]:
    """Plain Python softmax — avoids pulling numpy for the tiny output
    vector. Stable against overflow via max-subtraction."""
    import math

    if not logits:
        return []
    max_l = max(logits)
    exps = [math.exp(x - max_l) for x in logits]
    s = sum(exps)
    return [e / s for e in exps]
