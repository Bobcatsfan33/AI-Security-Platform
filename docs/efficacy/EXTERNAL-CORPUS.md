# External detection corpus

The CI efficacy gate includes the `deepset/prompt-injections` test split: 116
independently authored prompt-injection and benign examples. The upstream card
contains conflicting license declarations—Apache-2.0 at top level and
CC-BY-4.0 in `dataset_info`—so this repository conservatively treats the data
as CC-BY-4.0. Attribution: `deepset/prompt-injections`. The adaptation maps
numeric labels to `attack`/`benign`, adds stable row IDs, and writes normalized
JSONL; prompt text is unchanged.

The committed manifest records the exact upstream Git revision, source Parquet
digest, normalized JSONL digest, row counts, and license. The loader verifies
the normalized digest before scoring. This prevents an upstream edit or local
fixture change from silently moving the benchmark.

Regenerate the committed test artifact from its pinned source:

```bash
uv run --with pyarrow backend/scripts/refresh_external_detection_corpus.py
```

The bundled `deepset-char-logreg-v1` model is trained exclusively on the
separate 546-row upstream **train** split at the same immutable revision. Its
threshold is selected from five-fold out-of-fold training predictions under a
2.5% model false-positive budget. The exporter never reads this test split.
Regenerate the model and provenance manifest with pinned trainer versions:

```bash
uv run --with scikit-learn==1.9.0 --with pyarrow==25.0.0 \
  backend/scripts/train_prompt_injection_model.py
```

The runtime uses dependency-free TF-IDF/logistic inference and verifies the
committed artifact digest before loading. Exporter/runtime parity vectors guard
the feature and probability math.

Current held-out measurement for the complete security-detector ensemble when
every row is explicitly labeled `untrusted`: 49/60 attacks detected (81.7%)
and 0/56 benign samples flagged (0%). CI ratchets those values at an 80%
detection floor and 2% false-positive ceiling. The prior deterministic-only
baseline was 23/60 (38.3%) and 2/56 (3.6%).

This is a material independent-test improvement, not a launch claim. One small
public corpus does not establish production efficacy on customer traffic,
indirect injection, tool-call abuse, multi-turn attacks, or distribution
shift. The Fortune 500 release gate remains ≥90% recall with confidence
intervals across multiple independent frozen corpora plus customer replay,
with ≤5% false positives by deployment segment.

Source: <https://huggingface.co/datasets/deepset/prompt-injections>
