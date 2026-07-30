"""Checksum-verified, dependency-free prompt-injection model inference."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.detectors import util
from app.detectors.base import DetectorContext, DetectorResult, Direction

_MODEL_DIR = Path(__file__).with_name("models")
_MODEL_PATH = _MODEL_DIR / "prompt_injection_linear_v1.model.json"
_MANIFEST_PATH = _MODEL_DIR / "prompt_injection_linear_v1.manifest.json"
_MODEL_ID = "deepset-char-logreg-v1"
_THRESHOLD = 0.55
_WHITE_SPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class LinearPromptInjectionModel:
    model_id: str
    threshold: float
    intercept: float
    min_n: int
    max_n: int
    features: dict[str, tuple[float, float]]

    def score(self, text: str) -> tuple[float, int]:
        counts: Counter[str] = Counter()
        normalized = _WHITE_SPACE.sub(" ", text.lower())
        for word in normalized.split():
            padded = f" {word} "
            for width in range(self.min_n, self.max_n + 1):
                offset = 0
                counts[padded[offset : offset + width]] += 1
                while offset + width < len(padded):
                    offset += 1
                    counts[padded[offset : offset + width]] += 1
                if offset == 0:
                    break

        weighted: list[tuple[float, float]] = []
        for token, count in counts.items():
            values = self.features.get(token)
            if values:
                idf, coefficient = values
                weighted.append(((1.0 + math.log(count)) * idf, coefficient))
        norm = math.sqrt(sum(value * value for value, _ in weighted))
        logit = self.intercept
        if norm:
            logit += sum((value / norm) * coefficient for value, coefficient in weighted)
        if logit >= 0:
            probability = 1.0 / (1.0 + math.exp(-logit))
        else:
            exponential = math.exp(logit)
            probability = exponential / (1.0 + exponential)
        return probability, len(weighted)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"invalid prompt-injection model artifact: {message}")


@lru_cache(maxsize=1)
def load_prompt_injection_model() -> LinearPromptInjectionModel:
    model_bytes = _MODEL_PATH.read_bytes()
    manifest = json.loads(_MANIFEST_PATH.read_text())
    _require(
        hashlib.sha256(model_bytes).hexdigest() == manifest.get("artifact_sha256"),
        "checksum mismatch",
    )
    payload: dict[str, Any] = json.loads(model_bytes)
    _require(payload.get("schema_version") == 1, "unsupported schema")
    _require(payload.get("model_id") == _MODEL_ID, "unexpected model id")
    _require(payload.get("analyzer") == "char_wb", "unexpected analyzer")
    _require(payload.get("ngram_range") == [3, 5], "unexpected n-gram range")
    _require(payload.get("sublinear_tf") is True, "sublinear TF is required")
    _require(payload.get("norm") == "l2", "L2 normalization is required")
    _require(payload.get("lowercase") is True, "lowercase preprocessing is required")
    _require(payload.get("threshold") == _THRESHOLD, "threshold drift")
    raw_features = payload.get("features")
    _require(isinstance(raw_features, list) and len(raw_features) >= 1_000, "feature set")
    features: dict[str, tuple[float, float]] = {}
    for item in raw_features:
        _require(
            isinstance(item, list)
            and len(item) == 3
            and isinstance(item[0], str)
            and isinstance(item[1], (int, float))
            and isinstance(item[2], (int, float)),
            "malformed feature",
        )
        features[item[0]] = (float(item[1]), float(item[2]))
    _require(len(features) == len(raw_features), "duplicate features")
    intercept = float(payload.get("intercept"))
    _require(math.isfinite(intercept), "non-finite intercept")
    return LinearPromptInjectionModel(
        model_id=_MODEL_ID,
        threshold=_THRESHOLD,
        intercept=intercept,
        min_n=3,
        max_n=5,
        features=features,
    )


class PromptInjectionModelDetector:
    name = "prompt_injection_model"
    category = "prompt_injection"
    default_threshold = _THRESHOLD
    severity = "high"
    directions = (Direction.INBOUND,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        if ctx.extra.get("content_trust") != "untrusted":
            return DetectorResult(
                self.name,
                self.category,
                0.0,
                "info",
                {
                    "model_id": _MODEL_ID,
                    "reason": "classifier requires content_trust=untrusted",
                },
            )
        model = load_prompt_injection_model()
        score, matched_features = model.score(text)
        return DetectorResult(
            self.name,
            self.category,
            score,
            "critical" if score >= 0.9 else "high",
            {
                "model_id": model.model_id,
                "matched_features": matched_features,
                "band": util.band(score),
            },
        ).clamp()
