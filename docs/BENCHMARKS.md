# Runtime-agent benchmarks

Phase 2 turns the agent's latency from a *claim* into *evidence*. Until now the
README carried "sub-15ms added latency" as a **target, unmeasured** (GAP-002).
This document reports what is actually measured, how, and how to reproduce it.

**Two numbers, never conflated:**

1. **Pipeline-added latency** — the overhead of `policy.Pipeline.Evaluate`
   (`runtime-agent/policy/pipeline.go`). This is the product's "added latency"
   claim. **Measured here (increment 1).**
2. **End-to-end proxy overhead under sustained load** — the p99 an operator
   sees at the `:8400` proxy, measured over a real network path with the locust
   profile. **Increment 3** (this section will fill in then); it is deliberately
   NOT an httptest microbench, because a loopback microbench measures Go's test
   harness, not a deployment.

## Headline

> On the reference environment below, **`balanced` mode adds a p99 of 32.4 µs**
> of pipeline latency (Stage 1 + in-process heuristic Stage 2), and **`fast`
> mode a p99 of 27.2 µs** (Stage 1 only) — against the 15 ms target, ~460× and
> ~550× of margin. `comprehensive` across two mock sidecar hops (Stage 1+2+3,
> **no model inference** — see scope) is a p99 of 241 µs.

We lead with p99, not p50: the tail is what an SRE reads first, and a p50
headline reads as hiding the tail. **But read the tail caveat below** — a
single-request sampled p99 on a shared machine is noise-sensitive; the stable
signal is the mean / p50 (and the micro-benchmark allocs), and the
*authoritative* tail is the under-load locust p99 (increment 3).

## Measured — reference environment

Stamp: `go1.26.3`, `darwin/arm64` (Apple M2, 8 CPU), commit `efda453`, n=20000,
2026-07-27. These are single-request, in-process samples (no concurrency); the
**under-load** tail is the locust job (increment 3). These exact numbers are
committed in `runtime-agent/bench/measured.json` and pinned to this table by
`TestDocsMatchMeasured` — a divergence fails CI. Regenerate on your own hardware
with `runtime-agent/bench/regen.sh`.

### Latency distribution (single request, `Pipeline.Evaluate`)

| Mode | Stages run | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|---|
| `fast` | 1 (in-process) | 12.7 µs | 14.0 µs | 27.2 µs | 141.2 µs | 13.3 µs |
| `balanced` | 1 + 2 heuristic (in-process) | 23.8 µs | 27.9 µs | 32.4 µs | 126.2 µs | 24.4 µs |
| `comprehensive` | 1 + 2 + 3 (two sidecar hops, no inference) | 95.5 µs | 129.2 µs | 241.2 µs | 583.5 µs | 99.1 µs |

**Tail variance — read before quoting the p99.** These are single-request
samples on a shared laptop, and the tail is noise-dominated: across repeated
runs on identical code the `balanced` p99 ranged ~32–82 µs (and `fast`, being
only ~13 µs at the median, swung more in relative terms) — while p50 and mean
barely moved (±1 µs). More samples did **not** fix it (a longer run just
accumulates more scheduler/GC events). So: treat p50/mean and the deterministic
micro-benchmarks as the stable signals, and the sampled p99 as indicative with
~2× run-to-run variance. The **authoritative tail** is the under-load p99 from
the locust profile on a quiet host (increment 3) — that is what an operator
actually sees, and it is not a single-request microbench.

### Micro-benchmarks (`go test -bench`, allocations)

| Benchmark | ns/op (local) | B/op | allocs/op | gate signal |
|---|---|---|---|---|
| `Evaluate_Fast` | 16,879 | 225 | 2 | allocs/B (deterministic) |
| `Evaluate_BalancedHeuristic` | 36,591 | 514 | 3 | allocs/B (deterministic) |
| `Evaluate_ComprehensiveHeuristic` | 29,378 | 513 | 3 | allocs/B (deterministic) |
| `Evaluate_BalancedSidecar` | 65,100 | 10,958 | 109 | reported (localhost hop) |
| `Evaluate_ComprehensiveSidecar` | 126,601 | 22,626 | 219 | reported (two hops) |

`comprehensive` (heuristic) measuring ≈ `balanced` is expected, not an anomaly:
on a benign prompt the heuristic Stage 2 returns clean, so the Stage-3 judge
never fires — Stage 3 escalates only on an *uncertain* Stage-2 result, which the
sidecar rows exercise deliberately.

## Methodology (so the numbers are defensible)

- **Realistic input, realistic policy.** A benign prompt that does NOT match the
  ruleset, so the pipeline runs to completion (a matched prompt would
  short-circuit at Stage 1 and under-measure). The policy is a 12-pattern
  prompt-injection regex rule + a keyword rule, compiled through the same
  `CompileFromJSON` path production uses (`bench/harness.go`).
- **What the sidecar rows are — and are NOT.** The sidecar benchmarks route
  Stage 2/3 through a mock HTTP server at **zero added server delay**, so the
  number is the agent's *marshal + one-localhost-hop transport* cost. **It is
  NOT an ONNX inference-time claim.** Real inference is model-dependent and is
  measured in a POC with the actual model; it is explicitly out of scope here.
- **What is gated vs. reported** (the anti-flake split). The CI job
  `Agent bench gate` (pinned to `go1.26.3` — the toolchain the baseline was
  taken on) runs the benchmarks and pipes them through `bench/gate`
  (`runtime-agent/bench/gate/main.go`) against `bench/baseline.json`:
  - **`allocs/op` — gated exactly.** Hardware-independent (a function of the code
    path, identical on any CPU/OS given a pinned toolchain) and a variance-free
    integer count. Current > baseline for a deterministic benchmark fails the
    build. This is the primary signal.
  - **`B/op` — gated with a small (10%) tolerance.** It tracks allocations but
    carries ±1–2 bytes of jitter (the run's total is amortized over an auto-tuned
    N), so an exact gate would flake; the tolerance ignores the jitter and still
    catches a real byte-growth regression.
  - **`ns/op` — generous ~8× ceiling only.** ns/op is hardware-dependent (CI
    silicon ≠ the M2 baseline), so a *tight* ns bound would flake on the runner,
    get muted, and the gate would be worthless. It is checked only against
    `baseline_local × 8` — a gross-regression tripwire (a hot-path network call, a
    sleep, an O(n²)) with deliberate hardware headroom. **Do not tighten it into
    an absolute-latency assertion** — the rationale is in `gate/main.go`.
  - **Reported, never gated:** the p50/p95/p99 tail. Environment-sensitive, so it
    is published with a stamp and a regeneration command.
  - The sidecar benchmarks are `deterministic: false` in the baseline (they cross
    one/two localhost `net/http` hops whose allocations vary) — reported, not
    gated. Bumping `go1.26.3` means regenerating `baseline.json` in the same PR.
- **No cherry-picking, and the run is selected for measurement quality, not
  result.** Whatever `regen.sh` prints is what ships (had `balanced` missed
  15 ms, that number would be here and the README corrected to it — the entire
  point of GAP-002). The committed distribution is a **low-contention** run: runs
  where an unrelated process visibly stole CPU mid-sample (a max spike ≫ p99)
  were discarded as bad *measurements*, not bad *results* — and the doc and
  `measured.json` are locked together by `TestDocsMatchMeasured`, so the number
  you read is the number that was committed.

## Reproduce

```bash
cd runtime-agent && ./bench/regen.sh
```

Prints the micro-benchmark table and writes `bench/measured.json` (the latency
distribution + environment stamp, pinned to the doc table by
`TestDocsMatchMeasured`). Run it on the hardware you want to quote.

**Recommended conditions** — the sampled tail is noise-sensitive (see the tail
variance note above): a **quiet machine** (close other workloads), **AC power**
(no CPU-frequency throttling on battery), and expect the p99 to move ~2×
run-to-run regardless. p50/mean and the micro-benchmark allocs are stable; the
authoritative under-load tail is the locust profile (increment 3).
