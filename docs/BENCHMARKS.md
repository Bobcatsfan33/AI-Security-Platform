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

> On the reference environment below, **`balanced` mode adds a p99 of 34.6 µs**
> of pipeline latency (Stage 1 + in-process heuristic Stage 2), and **`fast`
> mode a p99 of 23.4 µs** (Stage 1 only) — against the 15 ms target, ~430× and
> ~640× of margin. `comprehensive` with a mock sidecar hop (Stage 1+2+3, **no
> model inference** — see scope) is a p99 of 226 µs.

We lead with p99, not p50: the tail is what an SRE reads first, and a p50
headline reads as hiding the tail.

## Measured — reference environment

Stamp: `go1.26.3`, `darwin/arm64` (Apple M2, 8 CPU), 2026-07-27. These are
single-request, in-process samples (no concurrency); the **under-load** tail is
the locust job (increment 3). Regenerate on your own hardware with
`runtime-agent/bench/regen.sh` — the numbers below are evidence precisely
because that command reproduces them.

### Latency distribution (single request, `Pipeline.Evaluate`)

| Mode | Stages run | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|---|
| `fast` | 1 (in-process) | 13.0 µs | 17.1 µs | 23.4 µs | 129.8 µs | 13.6 µs |
| `balanced` | 1 + 2 heuristic (in-process) | 24.2 µs | 30.4 µs | 34.6 µs | 150.6 µs | 25.2 µs |
| `comprehensive` | 1 + 2 + 3 (sidecar hop, no inference) | 96.8 µs | 132.2 µs | 226.5 µs | 427.7 µs | 101.8 µs |

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
- **What is gated vs. reported** (the anti-flake split):
  - **Gated (CI, increment 2):** `allocs/op` and `B/op` against
    `bench/baseline.json`. These are hardware-independent — identical on any
    CPU/OS — so an allocation regression is a variance-free signal. Plus a loose
    (~2×) `ns/op` ceiling that trips only on gross regressions.
  - **Reported (here):** the p50/p95/p99 tail. It is environment-sensitive, so
    it is published with a stamp and a regeneration command, never asserted in
    CI (an absolute-latency gate on shared CI runners flakes, then gets muted —
    the worst outcome).
- **No cherry-picking.** Whatever `regen.sh` prints is what ships. Had `balanced`
  missed 15 ms, that number would be here and the README claim corrected to it —
  which is the entire point of GAP-002.

## Reproduce

```bash
cd runtime-agent && ./bench/regen.sh
```

Prints the micro-benchmark table and writes `bench/measured.json` (the latency
distribution + environment stamp). Run it on the hardware you want to quote.
