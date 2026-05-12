"""Stage 2 ONNX engine tests — with stubbed backend + tokenizer.

Real ONNX inference is exercised by integration tests against a small
bundled model in CI (Sprint 3 follow-on). Here we test:
  - Spec loading from dict
  - Classifier dispatch + threshold gating
  - Highest-confidence selection across multiple classifiers
  - Latency tracking
  - Graceful degrade when a backend fails to load
  - Empty / disabled spec list → no-match
"""

from __future__ import annotations

from typing import Any

import pytest

from app.policy.compiled import compile_policy
from app.policy.stage2_onnx import (
    ClassifierSpec,
    OnnxClassifierStage2,
    _resolve_artifact_path,
    _softmax,
)
from app.policy.types import Direction, PolicyInput


def _input(text: str = "test") -> PolicyInput:
    return PolicyInput(text=text, direction=Direction.INBOUND)


def _policy() -> Any:
    return compile_policy(
        policy_row={
            "id": "p",
            "org_id": "org",
            "version": 1,
            "enforcement_level": "balanced",
            "fail_behavior": "open",
            "ml_confidence_threshold_high": 0.7,
            "ml_confidence_threshold_low": 0.3,
        }
    )


def _spec(**overrides: Any) -> ClassifierSpec:
    base = {
        "id": "pi-test",
        "name": "test classifier",
        "model_artifact_path": "file:///tmp/fake.onnx",
        "tokenizer_artifact_path": "file:///tmp/fake.json",
        "categories_detected": ("prompt_injection",),
        "threshold_per_label": {"prompt_injection": 0.5},
        "max_input_length": 1024,
        "enabled": True,
    }
    base.update(overrides)
    return ClassifierSpec(**base)


class _StubBackend:
    """Returns configured label probabilities."""

    def __init__(self, label_probs: dict[str, float]) -> None:
        self._probs = label_probs

    def classify(
        self, *, input_ids: list[int], attention_mask: list[int]
    ) -> dict[str, float]:
        return dict(self._probs)


class _StubTokenizer:
    """Returns fixed tokens regardless of input."""

    def encode(self, text: str, *, max_length: int) -> tuple[list[int], list[int]]:
        ids = [0, 1, 2, 3, 4][:max_length]
        return ids, [1] * len(ids)


def _stub_factory(label_probs: dict[str, float]):
    """Return factories that build the stub backend + tokenizer for any spec."""

    def backend_factory(spec: ClassifierSpec):
        return _StubBackend(label_probs)

    def tokenizer_factory(spec: ClassifierSpec):
        return _StubTokenizer()

    return backend_factory, tokenizer_factory


# ─────────────────────────────────────────── Spec parsing


@pytest.mark.unit
class TestSpec:
    def test_from_dict_full(self) -> None:
        spec = ClassifierSpec.from_dict(
            {
                "id": "pi-v3",
                "name": "Prompt injection",
                "model_artifact_path": "file:///models/pi.onnx",
                "tokenizer_artifact_path": "file:///models/pi-tok.json",
                "categories_detected": ["prompt_injection", "jailbreak"],
                "threshold_per_label": {"prompt_injection": 0.7},
                "max_input_length": 4096,
                "enabled": True,
            }
        )
        assert spec.id == "pi-v3"
        assert spec.categories_detected == ("prompt_injection", "jailbreak")
        assert spec.threshold_per_label == {"prompt_injection": 0.7}

    def test_from_dict_defaults(self) -> None:
        spec = ClassifierSpec.from_dict({"id": "x"})
        assert spec.id == "x"
        assert spec.categories_detected == ()
        assert spec.enabled is True
        assert spec.max_input_length == 8192


# ─────────────────────────────────────────── Engine — no specs


@pytest.mark.unit
@pytest.mark.asyncio
class TestNoSpecs:
    async def test_empty_specs_returns_no_match(self) -> None:
        engine = OnnxClassifierStage2(specs=[])
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is False
        assert result.action == "allowed"

    async def test_all_disabled_returns_no_match(self) -> None:
        engine = OnnxClassifierStage2(specs=[_spec(enabled=False)])
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is False


# ─────────────────────────────────────────── Threshold gating


@pytest.mark.unit
@pytest.mark.asyncio
class TestThresholdGating:
    async def test_below_threshold_no_match(self) -> None:
        b, t = _stub_factory({"prompt_injection": 0.4, "other": 0.6})
        engine = OnnxClassifierStage2(
            specs=[_spec(threshold_per_label={"prompt_injection": 0.5})],
            backend_factory=b,
            tokenizer_factory=t,
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        # 0.4 < threshold 0.5 → no match
        assert result.matched is False

    async def test_above_threshold_match(self) -> None:
        b, t = _stub_factory({"prompt_injection": 0.85})
        engine = OnnxClassifierStage2(
            specs=[_spec(threshold_per_label={"prompt_injection": 0.7})],
            backend_factory=b,
            tokenizer_factory=t,
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is True
        assert result.confidence == pytest.approx(0.85, abs=1e-6)
        assert result.category == "prompt_injection"
        assert result.rule_id == "pi-test"

    async def test_default_threshold_half(self) -> None:
        """If threshold_per_label doesn't list a label, default is 0.5."""
        b, t = _stub_factory({"prompt_injection": 0.55})
        engine = OnnxClassifierStage2(
            specs=[
                _spec(
                    categories_detected=("prompt_injection",),
                    threshold_per_label={},  # no per-label thresholds → default 0.5
                )
            ],
            backend_factory=b,
            tokenizer_factory=t,
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is True

    async def test_label_outside_categories_ignored(self) -> None:
        """If the model returns a label that ISN'T in categories_detected,
        we don't fire on it even with high confidence."""
        b, t = _stub_factory({"unrelated_label": 0.99})
        engine = OnnxClassifierStage2(
            specs=[
                _spec(
                    categories_detected=("prompt_injection",),
                    threshold_per_label={"prompt_injection": 0.5},
                )
            ],
            backend_factory=b,
            tokenizer_factory=t,
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is False


# ─────────────────────────────────────────── Multi-classifier selection


@pytest.mark.unit
@pytest.mark.asyncio
class TestMultiClassifier:
    async def test_highest_confidence_wins(self) -> None:
        b1, t1 = _stub_factory({"prompt_injection": 0.6})
        b2, t2 = _stub_factory({"jailbreak": 0.9})

        # We need different factories per spec ID — use a dispatcher
        def backend_factory(spec: ClassifierSpec):
            return _StubBackend({"prompt_injection": 0.6} if spec.id == "pi" else {"jailbreak": 0.9})

        def tokenizer_factory(spec: ClassifierSpec):
            return _StubTokenizer()

        engine = OnnxClassifierStage2(
            specs=[
                _spec(
                    id="pi",
                    categories_detected=("prompt_injection",),
                    threshold_per_label={"prompt_injection": 0.5},
                ),
                _spec(
                    id="jb",
                    categories_detected=("jailbreak",),
                    threshold_per_label={"jailbreak": 0.5},
                ),
            ],
            backend_factory=backend_factory,
            tokenizer_factory=tokenizer_factory,
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is True
        assert result.category == "jailbreak"
        assert result.rule_id == "jb"
        assert result.confidence == pytest.approx(0.9, abs=1e-6)


# ─────────────────────────────────────────── Resilience


@pytest.mark.unit
@pytest.mark.asyncio
class TestResilience:
    async def test_backend_load_failure_skips_classifier(self) -> None:
        def failing_backend(spec: ClassifierSpec):
            raise RuntimeError("model file not found")

        def stub_tokenizer(spec: ClassifierSpec):
            return _StubTokenizer()

        engine = OnnxClassifierStage2(
            specs=[_spec()],
            backend_factory=failing_backend,
            tokenizer_factory=stub_tokenizer,
        )
        # Failing classifier should NOT crash the engine — just no match
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is False

    async def test_infer_failure_skips_classifier(self) -> None:
        class _BoomBackend:
            def classify(self, *, input_ids, attention_mask):  # type: ignore[no-untyped-def]
                raise RuntimeError("inference crashed")

        engine = OnnxClassifierStage2(
            specs=[_spec()],
            backend_factory=lambda spec: _BoomBackend(),
            tokenizer_factory=lambda spec: _StubTokenizer(),
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.matched is False


# ─────────────────────────────────────────── Latency


@pytest.mark.unit
@pytest.mark.asyncio
class TestLatency:
    async def test_latency_recorded(self) -> None:
        b, t = _stub_factory({"prompt_injection": 0.8})
        engine = OnnxClassifierStage2(
            specs=[_spec()], backend_factory=b, tokenizer_factory=t
        )
        result = await engine.classify(input_=_input(), policy=_policy())
        assert result.latency_us >= 0
        # Sub-millisecond on stub paths, but allow CI noise
        assert result.latency_us < 100_000


# ─────────────────────────────────────────── Utilities


@pytest.mark.unit
class TestArtifactPathResolution:
    def test_file_prefix_stripped(self) -> None:
        assert _resolve_artifact_path("file:///tmp/x.onnx") == "/tmp/x.onnx"

    def test_absolute_path_returned_as_is(self) -> None:
        assert _resolve_artifact_path("/abs/path/x.onnx") == "/abs/path/x.onnx"

    def test_relative_path_resolved(self) -> None:
        from pathlib import Path

        out = _resolve_artifact_path("relative/x.onnx")
        assert Path(out).is_absolute()

    def test_remote_scheme_raises(self) -> None:
        for url in (
            "s3://bucket/key.onnx",
            "https://cdn.example/x.onnx",
            "http://localhost/x.onnx",
        ):
            with pytest.raises(NotImplementedError):
                _resolve_artifact_path(url)


@pytest.mark.unit
class TestSoftmax:
    def test_uniform_input(self) -> None:
        probs = _softmax([1.0, 1.0, 1.0])
        assert all(abs(p - 1 / 3) < 1e-9 for p in probs)

    def test_sums_to_one(self) -> None:
        probs = _softmax([2.0, -1.0, 0.5, 3.0])
        assert abs(sum(probs) - 1.0) < 1e-9

    def test_stable_with_large_values(self) -> None:
        # No overflow even with values that would naively overflow exp()
        probs = _softmax([1000.0, 1001.0, 999.0])
        assert all(0 <= p <= 1 for p in probs)
        assert abs(sum(probs) - 1.0) < 1e-9

    def test_empty(self) -> None:
        assert _softmax([]) == []
