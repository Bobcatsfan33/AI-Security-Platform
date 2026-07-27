#!/usr/bin/env bash
# Regenerate the runtime-agent pipeline benchmark evidence.
#
# A number nobody can regenerate is a claim; a number anyone can regenerate is
# evidence. This is the one command that produces both the micro-benchmark
# figures (ns/op + allocs/op + B/op) and the p50/p95/p99 latency distribution
# (bench/measured.json), stamped with the environment they were produced on.
#
# Usage (from runtime-agent/):   ./bench/regen.sh
# Then paste the printed table into docs/BENCHMARKS.md and update its stamp, or
# copy bench/measured.json's env block. Run on the hardware you want to quote.
set -euo pipefail
cd "$(dirname "$0")/.."

commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "# runtime-agent benchmark regeneration"
echo "# commit=${commit}  go=$(go version | awk '{print $3}')  $(uname -sm)"
echo

echo "## Micro-benchmarks (ns/op, B/op, allocs/op)"
go test -bench=. -benchmem -run='^$' -benchtime=2s ./bench/

echo
echo "## Latency distribution (writes bench/measured.json)"
BENCH_WRITE=1 go test -run TestLatencyDistribution -v ./bench/ 2>&1 | grep -E 'p50=|wrote'
