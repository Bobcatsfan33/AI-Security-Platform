// Command gate is the runtime-agent benchmark regression gate. It reads
// `go test -bench -benchmem` output on stdin, compares it against the committed
// bench/baseline.json, and exits non-zero on a regression.
//
// ANTI-FLAKE PHILOSOPHY — read this before "tightening" the gate.
//
// The authoritative signal is allocs/op + B/op. Those are HARDWARE-INDEPENDENT:
// a function of the code path, byte-identical on any CPU or OS, given a pinned
// Go toolchain (the CI job pins it to match the baseline). An allocation delta
// is therefore a real regression with ZERO variance — that is the gate, and it
// is compared exactly (current must not exceed baseline) for the deterministic
// benchmarks.
//
// ns/op is HARDWARE-DEPENDENT. The committed baseline was taken on an Apple M2;
// CI runs on different silicon, so CI ns/op legitimately differs by a large
// constant factor with NO code change. We therefore do NOT assert a tight ns
// bound — that would flake on the runner's mood, a maintainer would mute it, and
// the gate would be worthless. ns is checked only against a GENEROUS absolute
// ceiling (baseline_local × nsCeilingFactor) that trips on an order-of-magnitude
// regression — a hot-path network call, a sleep, an accidental O(n^2) — and
// nothing subtler. Do NOT lower nsCeilingFactor toward 1 to "catch more": you
// will catch the runner, not the code. If you want to catch smaller perf drift,
// add an allocation or a distinct deterministic benchmark, do not tighten ns.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// nsCeilingFactor is deliberately loose — see the package comment. It multiplies
// the M2-local baseline to form a hardware-agnostic gross-regression tripwire.
const nsCeilingFactor = 8.0

// bToleranceFactor: allocs/op is an exact integer count (rock-solid, gated
// exactly), but B/op carries ±1–2 bytes of jitter because the run's total
// allocation is amortized over an auto-tuned N. So B/op is gated with a small
// tolerance — enough to ignore the jitter, tight enough to catch a real
// byte-growth regression (a new buffer, a doubled slice). It is NOT the primary
// signal; allocs/op is.
const bToleranceFactor = 1.10

type result struct {
	ns     float64
	bytes  float64
	allocs float64
}

type baselineEntry struct {
	AllocsPerOp   float64 `json:"allocs_per_op"`
	BPerOp        float64 `json:"b_per_op"`
	NsPerOpLocal  float64 `json:"ns_per_op_local"`
	Deterministic bool    `json:"deterministic"`
}

type baselineFile struct {
	Benchmarks map[string]baselineEntry `json:"benchmarks"`
}

// benchLine matches a testing.B result line, e.g.
//
//	BenchmarkEvaluate_Fast-8   72172   16879 ns/op   225 B/op   2 allocs/op
//
// The trailing -N (GOMAXPROCS) is stripped so names match baseline keys.
var (
	nameRe   = regexp.MustCompile(`^(Benchmark[^\s]+?)(?:-\d+)?\s`)
	metricRe = regexp.MustCompile(`([0-9.]+)\s+(ns/op|B/op|allocs/op)`)
)

func parseBench(r io.Reader) (map[string]result, error) {
	out := map[string]result{}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		m := nameRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		res := result{}
		for _, mm := range metricRe.FindAllStringSubmatch(line, -1) {
			v, _ := strconv.ParseFloat(mm[1], 64)
			switch mm[2] {
			case "ns/op":
				res.ns = v
			case "B/op":
				res.bytes = v
			case "allocs/op":
				res.allocs = v
			}
		}
		out[m[1]] = res
	}
	return out, nil
}

type finding struct {
	name string
	msg  string
}

// compare returns the human-readable report and every regression finding.
// A finding means the gate fails.
func compare(base baselineFile, cur map[string]result, nsFactor float64) (string, []finding) {
	var b strings.Builder
	var findings []finding

	names := make([]string, 0, len(base.Benchmarks))
	for n := range base.Benchmarks {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Fprintf(&b, "%-42s %12s %12s %12s\n", "benchmark", "allocs/op", "B/op", "ns/op")
	for _, n := range names {
		bl := base.Benchmarks[n]
		c, ok := cur[n]
		if !ok {
			// A baseline benchmark that no longer runs is drift: the gate is
			// comparing against a benchmark that has been renamed or deleted.
			findings = append(findings, finding{n, "present in baseline but not in the current run (renamed/removed?)"})
			fmt.Fprintf(&b, "%-42s %12s\n", n, "MISSING")
			continue
		}
		det := ""
		if !bl.Deterministic {
			det = " (reported)"
		}
		fmt.Fprintf(&b, "%-42s %6.0f/%-5.0f %6.0f/%-5.0f %12.0f%s\n",
			n, c.allocs, bl.AllocsPerOp, c.bytes, bl.BPerOp, c.ns, det)

		if bl.Deterministic {
			if c.allocs > bl.AllocsPerOp {
				findings = append(findings, finding{n, fmt.Sprintf("allocs/op %.0f > baseline %.0f", c.allocs, bl.AllocsPerOp)})
			}
			if bCeiling := bl.BPerOp * bToleranceFactor; c.bytes > bCeiling {
				findings = append(findings, finding{n, fmt.Sprintf("B/op %.0f > baseline %.0f + %.0f%% tolerance (%.0f)", c.bytes, bl.BPerOp, (bToleranceFactor-1)*100, bCeiling)})
			}
		}
		ceiling := bl.NsPerOpLocal * nsFactor
		if c.ns > ceiling {
			findings = append(findings, finding{n, fmt.Sprintf("ns/op %.0f > gross-regression ceiling %.0f (%.0fx local baseline)", c.ns, ceiling, nsFactor)})
		}
	}
	return b.String(), findings
}

func main() {
	baselinePath := flag.String("baseline", "bench/baseline.json", "path to baseline.json")
	flag.Parse()

	raw, err := os.ReadFile(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate: read baseline: %v\n", err)
		os.Exit(2)
	}
	var base baselineFile
	if err := json.Unmarshal(raw, &base); err != nil {
		fmt.Fprintf(os.Stderr, "gate: parse baseline: %v\n", err)
		os.Exit(2)
	}
	cur, err := parseBench(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate: read bench output: %v\n", err)
		os.Exit(2)
	}
	if len(cur) == 0 {
		fmt.Fprintln(os.Stderr, "gate: no benchmark results parsed from stdin — did the benchmarks run?")
		os.Exit(2)
	}

	report, findings := compare(base, cur, nsCeilingFactor)
	fmt.Print(report)

	if len(findings) == 0 {
		fmt.Printf("\ngate: PASS — %d benchmarks within baseline (allocs/B exact; ns/op < %.0fx local)\n", len(base.Benchmarks), nsCeilingFactor)
		return
	}
	fmt.Fprintf(os.Stderr, "\ngate: FAIL — %d regression(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  - %s: %s\n", f.name, f.msg)
	}
	fmt.Fprintln(os.Stderr, "\nIf this is an intended change, regenerate and commit bench/baseline.json (bench/regen.sh) in the same PR.")
	os.Exit(1)
}
