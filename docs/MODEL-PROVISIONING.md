# Inline ML Model Provisioning (Stage 2 ONNX)

How a trained prompt-injection / jailbreak classifier is built, versioned,
signed, and delivered to a runtime-agent deployment so the agent runs **ONNX
inference inline** at Stage 2 instead of the zero-config heuristic.

## Where the model runs

The Go agent stays a single static binary; the model runs in a co-located
**inference sidecar** the agent calls over localhost HTTP (`HTTPStage2`,
`runtime-agent/policy/stage2_http.go`). This avoids CGo/ONNX-Runtime linkage in
the agent while keeping inference one hop away on the same pod.

```
request → agent (Stage 1 regex) → Stage 2: POST http://127.0.0.1:9100/classify
                                            {"text": "...", "max_length": 8192}
                                   ← {"matched": true, "confidence": 0.93, "category": "prompt_injection"}
```

Set `STAGE2_ONNX_ENDPOINT=http://127.0.0.1:9100/classify` on the agent to
activate it; unset → heuristic Stage 2. `STAGE2_TIMEOUT` (default 150ms) bounds
the hot-path cost; a slow/down sidecar fails **open** (request still gets
Stage 1 + Stage 3).

## Build → version → sign → deliver

1. **Train / fine-tune.** Base model: `protectai/deberta-v3-base-prompt-injection-v2`
   (or an org-specific fine-tune). The control plane's Stage 2 engine
   (`backend/app/policy/stage2_onnx.py`) already loads ONNX + tokenizer and
   produces calibrated scores — reuse its `ClassifierSpec` shape.
2. **Export to ONNX** with the tokenizer; record `id2label` in the model
   metadata (the Python loader reads it).
3. **Version.** Tag each artifact `pi-classifier-vN`; record it in the
   **AI-BOM** (`backend/app/aibom/`) so the model is a tracked supply-chain
   component with a risk score (`aibom/risk.py`) and drift detection
   (`aibom/drift.py`).
4. **Sign.** Sign the `.onnx` + tokenizer with the platform signing key; the
   sidecar verifies the signature on load (provenance — feeds AI-BOM
   supply-chain risk). Distribute via the same channel as pattern content
   (signed, versioned artifacts — see Sprint 10 pattern library).
5. **Deliver.** Mount the signed artifact into the sidecar (init container
   pulls the versioned artifact from object storage; checksum-verified).

## Provisioning the artifact (Phase 1A — implemented)

The mechanism above is now concrete and checksum-pinned end to end. Two pieces
ship in the repo; only the artifact itself is produced out-of-band (it is too
large to commit).

### 1. Export the artifact (operational, once per model version)

```bash
pip install "optimum[exporters,onnxruntime]" transformers
python backend/scripts/export_stage2_onnx.py \
    --model protectai/deberta-v3-base-prompt-injection-v2 \
    --out ./dist/stage2 --quantize
```

This writes `stage2_model.onnx` + `stage2_tokenizer.json` and prints their
SHA-256s. Attach both files to a GitHub release (or push to your object store).

> **Hosted artifact (live).** A v1 export is already published and pinned as the
> Helm/`.env.example` default — a fresh deploy runs the real model out of the box:
> [`stage2-pi-classifier-v1`](https://github.com/Bobcatsfan33/AI-Security-Platform/releases/tag/stage2-pi-classifier-v1).
> Model SHA-256 `1dc9297b…78ee`, tokenizer `133b1071…a903`. Verified end-to-end
> from the public URL: injection → `prompt_injection` 1.0, benign → clean. Only
> re-run the export above to ship a new model version.

### 2. Pin the checksums into the deployment env

The control plane provisions the artifact at startup
(`backend/app/provisioning/model_provision.py`): it downloads from the URL,
**verifies the SHA-256 before use** (a tampered/truncated download is rejected,
never loaded), and caches the verified file so restarts don't re-download.
`file://` and `http(s)://` are both supported.

```bash
STAGE2_ONNX_MODEL_URL=https://github.com/<org>/<repo>/releases/download/pi-classifier-v1/stage2_model.onnx
STAGE2_ONNX_MODEL_SHA256=<printed by the export script>
STAGE2_ONNX_TOKENIZER_URL=https://.../stage2_tokenizer.json
STAGE2_ONNX_TOKENIZER_SHA256=<printed by the export script>
MODEL_CACHE_DIR=/var/cache/aisp/models   # default
```

Leave `STAGE2_ONNX_MODEL_URL` unset → the deterministic heuristic Stage 2 runs
instead, and every verdict is labelled `mode="stage2_heuristic"`. The platform
never reports an ML verdict it didn't compute.

### 3. Serving options

- **In-process (control plane):** `POST /v1/aiguard/classify` (scope
  `runtime:ingest`) serves the provisioned model directly — same
  `{matched, confidence, category}` body the agent's `HTTPStage2` expects, plus
  a `mode` field (`stage2_onnx` | `stage2_heuristic`). Point the agent's
  `STAGE2_ONNX_ENDPOINT` at this route to skip the separate sidecar.
- **Sidecar:** the localhost sidecar described above, for deployments that want
  inference off the control-plane process.

## Confidence routing (unchanged by backend)

The pipeline routes on the sidecar's `confidence` exactly as for the heuristic:
high band → act at Stage 2; uncertain band → escalate to Stage 3 (LLM judge)
under `comprehensive` enforcement. Thresholds come from the policy
(`ml_confidence_threshold_high/low`).

## Latency budget

Stage 2 is in the request hot path. Measure added p99 on every model change;
keep `STAGE2_TIMEOUT` tight (≤150ms). Stage 3 (LLM judge) is the slow path and
is invoked **only** for the uncertain band under `comprehensive`, with its own
strict timeout (`STAGE3_TIMEOUT`, default 3s) and fail-open/closed per policy.
