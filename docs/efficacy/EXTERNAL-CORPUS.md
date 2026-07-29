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

Regenerate the committed artifact from its pinned source:

```bash
uv run --with pyarrow backend/scripts/refresh_external_detection_corpus.py
```

This external set measures the deterministic AI Guard prompt-injection path. It
does not prove production efficacy on customer traffic, multilingual traffic,
indirect injection, tool-call abuse, or multi-turn attacks. Those require
separate frozen corpora and design-partner replay evidence.

Initial measurement after adding generalized override-language detection:
23/60 attacks detected (38.3%) and 2/56 benign samples flagged (3.6%). CI
ratchets those values at a 35% detection floor and 5% false-positive ceiling.
Those are regression bounds, not acceptable launch claims; the production-model
track must raise detection materially without exceeding the false-positive
budget.

Source: <https://huggingface.co/datasets/deepset/prompt-injections>
