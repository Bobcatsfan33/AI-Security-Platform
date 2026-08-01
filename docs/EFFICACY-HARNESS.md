# Detection efficacy harness (P15a)

> **This is the harness, not the evidence.** Every corpus shipped here is
> synthetic and says so in its manifest, in the JSON report, and in a banner at
> the top of every receipt. **EXT-EFFICACY remains open and blocking.** It needs
> two things this sprint does not provide: authorized corpora sampled from real
> deployments, and an evaluation run by an independent party.

## What it does

Reads hash-pinned labeled corpora, runs them through **every promoted detection
surface**, and reports precision, recall, false-positive rate, detection
latency, and confidence intervals **per slice** — because an aggregate number
hides exactly the failures that matter.

The shipped synthetic run demonstrates the point:

| surface | slice | recall | FPR |
|---|---|---|---|
| prompt_injection | overall | 0.6875 | 0.30 |
| prompt_injection | multilingual | **0.2500** | **0.50** |
| prompt_injection | encoded_obfuscated | 1.0000 | n/a |
| prompt_injection | benign_hard_negative | n/a | **0.40** |
| behavioural | overall | 0.4000 | 0.00 |

An aggregate "0.69 recall" would have concealed that non-English attacks are
caught a quarter of the time while half of benign non-English traffic is
flagged. That asymmetry is the product of a slice-blind report, and it is the
reason slices are first-class here rather than a tag on a case.

## Two evaluated surfaces, not one

Measuring only the injection models is how a suite comes to report excellent
efficacy for a system whose behavioural half was never exercised.

- **`prompt_injection`** — content inspection through the real AI Guard service,
  including the decode/normalize pre-pass and the Stage-2 classifier. The
  report binds `stage2_mode`, because the same corpus scores very differently
  under a verified ONNX model than under the heuristic fallback.
- **`behavioural`** — the attack-graph / anomaly path: per-agent EPAs plus the
  cross-agent correlation layer, driven by event **sequences**. A fresh fleet
  per case, because these detectors are stateful and a shared one would let
  case *N* decide case *N+1*'s verdict.

**Reading the behavioural numbers.** The report binds `maturity_min=50`: a
per-agent envelope learns but does not alert until it has seen 50 events. The
shipped sequences are 4–20 events, so **only the cross-agent correlation
signals can fire on them**. `behavioural recall 0.40` therefore measures the
correlation layer, not the per-agent detectors — which is why the binding is in
the report rather than left for a reader to guess. Exercising the per-agent
path needs longer sequences; that is a corpus gap, not a detector result.

## Slice axes

`multilingual`, `multi_turn`, `indirect_injection`, `tool_call_abuse`,
`encoded_obfuscated`, `benign_hard_negative` — a **closed set** (an unknown
slice name in a manifest is refused, because a misspelled axis creates a silent,
empty, always-passing dimension).

Plus `customer_distribution`, which is different: it **refuses**. It is the
number a buyer actually cares about and the easiest one to fake — point it at
synthetic data, report a high score, and nothing says the distribution was
invented. Running it without an authorized corpus records it as *unevaluated
with a reason* in the report, or raises `NoAuthorizedCorpus` in the explicit
form. There is no fallback path, because a fallback is how substitution happens.

## Manifests

Every field is required and loading fails rather than defaulting:

| field | why it is not optional |
|---|---|
| `provenance` | source, collector, date, license, authorization. A corpus nobody is allowed to use is a liability, not evidence. |
| `labeling_protocol` | method, labelers, adjudication, agreement. Metrics against labels of unknown quality measure the labeler. |
| `sha256` | the exact bytes. Without it a report names a filename, and files change. |
| `split` | `train` / `calibration` / `test`, declared so overlap can be refused. |
| `representative` | defaults `false`; setting it `true` **requires** a named `authorization`. This is the one claim that cannot be self-asserted. |

**Leakage is refused, not reported.** Overlap is detected on case *content*, not
id — because leakage happens when corpora are assembled by copy-paste, under
different ids. The check runs across the whole manifest set before any metric is
computed: every number would be wrong if splits overlap, so there is no point
producing them first. Only the `test` split is ever scored.

## Running it

```sh
cd backend
python -m scripts.run_efficacy \
  --manifest app/efficacy/corpora/synthetic-text-test.manifest.json \
  --manifest app/efficacy/corpora/synthetic-events-test.manifest.json \
  --out ../docs/evidence/p15 \
  --checkpoint /tmp/efficacy.ckpt      # optional: resumable
```

Runs are **deterministic** (sorted case order, no sampling) and **resumable**
(verdicts appended to the checkpoint as produced; a resumed run replays them).
Output: `docs/evidence/p15/efficacy-report.json` and `-receipt.txt`.

## Adding an authorized corpus

1. Write the corpus as JSONL (`id`, `kind`, `label`, `payload`, `slices`).
2. Write a manifest with complete `provenance` and `labeling_protocol`, the
   file's real `sha256`, and its `split`.
3. Set `representative: true` **and** `authorization` to the agreement or
   approval that permits it. Without the second, loading fails.
4. Re-run. The evidence class flips to `authorized-corpus` — and note that a
   single synthetic corpus in the set taints the whole run back to
   `synthetic-demonstration`, deliberately: mixing does not average out to
   "mostly evidence".

Even then, EXT-EFFICACY needs an **independent evaluator**. Running your own
harness against your own corpora and publishing the result is a demonstration.

## Self-tests

`backend/tests/unit/test_efficacy_harness.py` (55 tests). The scoring maths is
checked against corpora whose metrics are computable on paper (TP=4, FN=2, FP=1,
TN=3 → precision 0.8, recall 0.667, FPR 0.25), the Wilson interval against a
textbook value, and every refusal the harness claims is made to fire — including
a deliberately-leaky manifest pair with identical content under different ids.
