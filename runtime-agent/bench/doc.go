// Package bench is the runtime-agent's pipeline benchmark + latency-measurement
// harness. It measures PIPELINE-ADDED latency — the overhead of
// policy.Pipeline.Evaluate, which is the product's "added latency" claim — per
// enforcement mode (fast / balanced / comprehensive), against representative
// input and a realistic ruleset.
//
// Two kinds of number come out of here, and they are never conflated:
//
//   - Go micro-benchmarks (BenchmarkEvaluate_*) report ns/op + allocs/op + B/op.
//     The allocation figures are variance-free and are what the CI regression
//     gate compares against bench/baseline.json (see docs/BENCHMARKS.md).
//   - A percentile sampler (TestLatencyDistribution) reports p50/p95/p99 of
//     single-request Evaluate latency. These are the headline numbers published
//     in docs/BENCHMARKS.md; they are REPORTED, not gated (see the gate's
//     anti-flake design in docs/BENCHMARKS.md).
//
// Scope: this harness measures Evaluate in-process. END-TO-END proxy overhead
// and tail latency UNDER SUSTAINED LOAD are measured separately by the locust
// profile against the live :8400 proxy (a real network path, not an httptest
// loopback) — see docs/BENCHMARKS.md. The mock-sidecar numbers here measure the
// agent's marshal/transport cost across one localhost hop; they are NOT an
// ONNX inference-time claim (real inference is model-dependent and measured in a
// POC with the actual model).
package bench
