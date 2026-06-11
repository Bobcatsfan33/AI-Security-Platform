"""Export the Stage-2 prompt-injection classifier to ONNX + emit its SHA-256.

This is an **operational / release** script — it is not run in CI and not on the
serving hot path. It produces the two artifacts the runtime provisions at
startup (see ``app/provisioning/model_provision.py`` and
``docs/MODEL-PROVISIONING.md``):

    stage2_model.onnx       # the exported, optionally-quantized classifier
    stage2_tokenizer.json   # the matching fast-tokenizer

Run it once per model version, attach both files to a GitHub release (or push to
your object store), then pin the printed SHA-256s into the deployment env:

    STAGE2_ONNX_MODEL_URL / STAGE2_ONNX_MODEL_SHA256
    STAGE2_ONNX_TOKENIZER_URL / STAGE2_ONNX_TOKENIZER_SHA256

Usage:
    python scripts/export_stage2_onnx.py \
        --model protectai/deberta-v3-base-prompt-injection-v2 \
        --out ./dist/stage2 [--quantize]

Requires the (heavy, dev-only) export extras:
    pip install "optimum[exporters,onnxruntime]" transformers
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

_CHUNK = 1 << 20


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def export(model_id: str, out_dir: Path, *, quantize: bool) -> None:
    # Imported lazily so the heavy export stack is never a runtime/CI dependency.
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer
    except ImportError as exc:  # pragma: no cover - operational guard
        sys.exit(
            "export extras missing — install with:\n"
            '    pip install "optimum[exporters,onnxruntime]" transformers\n'
            f"({exc})"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"exporting {model_id} → {out_dir} (quantize={quantize})")

    model = ORTModelForSequenceClassification.from_pretrained(model_id, export=True)
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)

    if quantize:
        from optimum.onnxruntime import ORTQuantizer
        from optimum.onnxruntime.configuration import AutoQuantizationConfig

        quantizer = ORTQuantizer.from_pretrained(out_dir)
        qconfig = AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=False)
        quantizer.quantize(save_dir=out_dir, quantization_config=qconfig)

    # Normalise to the two artifact names the provisioner expects.
    onnx_src = next(out_dir.glob("*quantized*.onnx" if quantize else "model.onnx"), None)
    if onnx_src is None:
        onnx_src = next(out_dir.glob("*.onnx"))
    model_dst = out_dir / "stage2_model.onnx"
    if onnx_src.resolve() != model_dst.resolve():
        model_dst.write_bytes(onnx_src.read_bytes())
    tok_dst = out_dir / "stage2_tokenizer.json"
    tok_src = out_dir / "tokenizer.json"
    if tok_src.exists() and tok_src.resolve() != tok_dst.resolve():
        tok_dst.write_bytes(tok_src.read_bytes())

    print("\nartifacts ready — pin these into the deployment env:")
    print(f"  STAGE2_ONNX_MODEL_SHA256={_sha256(model_dst)}  # {model_dst.name}")
    if tok_dst.exists():
        print(f"  STAGE2_ONNX_TOKENIZER_SHA256={_sha256(tok_dst)}  # {tok_dst.name}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--model",
        default="protectai/deberta-v3-base-prompt-injection-v2",
        help="HF model id of the prompt-injection sequence classifier to export",
    )
    p.add_argument("--out", type=Path, default=Path("./dist/stage2"), help="output directory")
    p.add_argument("--quantize", action="store_true", help="dynamic-quantize for CPU serving")
    args = p.parse_args()
    export(args.model, args.out, quantize=args.quantize)


if __name__ == "__main__":
    main()
