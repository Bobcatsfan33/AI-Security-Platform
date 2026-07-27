package main

import (
	"strings"
	"testing"
)

const sampleOutput = `
goos: linux
goarch: amd64
pkg: github.com/Bobcatsfan33/ai-security-platform/runtime-agent/bench
cpu: some x86 runner
BenchmarkEvaluate_Fast-4                    50000    41000 ns/op    225 B/op    2 allocs/op
BenchmarkEvaluate_BalancedSidecar-4         10000   140000 ns/op  10958 B/op  109 allocs/op
PASS
`

func TestParseBenchStripsSuffixAndReadsMetrics(t *testing.T) {
	got, err := parseBench(strings.NewReader(sampleOutput))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got["BenchmarkEvaluate_Fast"]
	if !ok {
		t.Fatalf("Fast not parsed; got keys %v", keys(got))
	}
	if f.allocs != 2 || f.bytes != 225 || f.ns != 41000 {
		t.Errorf("Fast = %+v, want allocs=2 bytes=225 ns=41000", f)
	}
	if _, ok := got["BenchmarkEvaluate_BalancedSidecar"]; !ok {
		t.Errorf("sidecar bench not parsed")
	}
}

func baseline() baselineFile {
	return baselineFile{Benchmarks: map[string]baselineEntry{
		"BenchmarkEvaluate_Fast":            {AllocsPerOp: 2, BPerOp: 225, NsPerOpLocal: 16879, Deterministic: true},
		"BenchmarkEvaluate_BalancedSidecar": {AllocsPerOp: 109, BPerOp: 10958, NsPerOpLocal: 65100, Deterministic: false},
	}}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		name      string
		cur       map[string]result
		wantFail  bool
		wantInMsg string
	}{
		{
			name: "clean run on slower hardware passes",
			// ns ~2.4x the M2 baseline (a slower runner) — must NOT fail.
			cur: map[string]result{
				"BenchmarkEvaluate_Fast":            {ns: 41000, bytes: 225, allocs: 2},
				"BenchmarkEvaluate_BalancedSidecar": {ns: 150000, bytes: 10958, allocs: 109},
			},
			wantFail: false,
		},
		{
			name: "B/op jitter within tolerance does not flake",
			// 240 vs baseline 225 is +6.7%, under the 10% tolerance — must pass.
			cur: map[string]result{
				"BenchmarkEvaluate_Fast":            {ns: 41000, bytes: 240, allocs: 2},
				"BenchmarkEvaluate_BalancedSidecar": {ns: 150000, bytes: 10958, allocs: 109},
			},
			wantFail: false,
		},
		{
			name: "one extra alloc on a deterministic bench fails",
			cur: map[string]result{
				"BenchmarkEvaluate_Fast":            {ns: 41000, bytes: 225, allocs: 3},
				"BenchmarkEvaluate_BalancedSidecar": {ns: 150000, bytes: 10958, allocs: 109},
			},
			wantFail:  true,
			wantInMsg: "allocs/op 3 > baseline 2",
		},
		{
			name: "more bytes on a deterministic bench fails",
			cur: map[string]result{
				"BenchmarkEvaluate_Fast":            {ns: 41000, bytes: 400, allocs: 2},
				"BenchmarkEvaluate_BalancedSidecar": {ns: 150000, bytes: 10958, allocs: 109},
			},
			wantFail:  true,
			wantInMsg: "B/op 400 > baseline 225",
			// (message continues "+ 10% tolerance (248)"; prefix match is enough)
		},
		{
			name: "sidecar (non-deterministic) alloc increase is reported, not gated",
			cur: map[string]result{
				"BenchmarkEvaluate_Fast":            {ns: 41000, bytes: 225, allocs: 2},
				"BenchmarkEvaluate_BalancedSidecar": {ns: 150000, bytes: 20000, allocs: 200},
			},
			wantFail: false,
		},
		{
			name: "gross ns regression trips the ceiling",
			cur: map[string]result{
				// 16879 * 8 = 135032 ceiling; 200000 blows through it.
				"BenchmarkEvaluate_Fast":            {ns: 200000, bytes: 225, allocs: 2},
				"BenchmarkEvaluate_BalancedSidecar": {ns: 150000, bytes: 10958, allocs: 109},
			},
			wantFail:  true,
			wantInMsg: "gross-regression ceiling",
		},
		{
			name: "a removed/renamed baseline bench is drift and fails",
			cur: map[string]result{
				"BenchmarkEvaluate_Fast": {ns: 41000, bytes: 225, allocs: 2},
			},
			wantFail:  true,
			wantInMsg: "not in the current run",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, findings := compare(baseline(), tc.cur, nsCeilingFactor)
			if (len(findings) > 0) != tc.wantFail {
				t.Fatalf("wantFail=%v; findings=%v\nreport:\n%s", tc.wantFail, findings, report)
			}
			if tc.wantInMsg != "" {
				joined := ""
				for _, f := range findings {
					joined += f.msg + "\n"
				}
				if !strings.Contains(joined, tc.wantInMsg) {
					t.Errorf("want a finding containing %q; got:\n%s", tc.wantInMsg, joined)
				}
			}
		})
	}
}

func keys(m map[string]result) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
