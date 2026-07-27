package bench

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestDocsMatchMeasured is the doc-vs-artifact ratchet: the p99 figures quoted
// in the docs/BENCHMARKS.md distribution table MUST match bench/measured.json
// within rounding. Numbers that live in two places diverge — this makes the
// divergence fail CI, the same instinct as the tier table and the lock-drift
// checks. The incident that earned it: a stray regen wrote a measured.json whose
// p99 (73 µs) silently contradicted the 34.6 µs the docs still quoted.
//
// This runs in the normal test suite (it is cheap — two file reads). The heavy
// sampler that PRODUCES measured.json is regeneration-only (BENCH_WRITE=1).
func TestDocsMatchMeasured(t *testing.T) {
	raw, err := os.ReadFile("measured.json")
	if err != nil {
		t.Fatalf("read measured.json: %v", err)
	}
	var report struct {
		Distributions []Percentiles `json:"distributions"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("parse measured.json: %v", err)
	}

	// Guard the vacuous-pass corner: an empty distributions array would make the
	// loop below assert nothing. We know exactly three modes are sampled.
	if len(report.Distributions) != 3 {
		t.Fatalf("measured.json has %d distributions, want 3 (fast/balanced/comprehensive) — regenerate with bench/regen.sh", len(report.Distributions))
	}

	md, err := os.ReadFile("../../docs/BENCHMARKS.md")
	if err != nil {
		t.Fatalf("read BENCHMARKS.md: %v", err)
	}
	docP99 := parseDocTableP99(string(md))

	for _, d := range report.Distributions {
		key := strings.SplitN(d.Mode, " ", 2)[0] // fast | balanced | comprehensive
		got, ok := docP99[key]
		if !ok {
			t.Errorf("mode %q from measured.json has no p99 row in the BENCHMARKS.md distribution table", key)
			continue
		}
		want := round1(d.P99US)
		if got != want {
			t.Errorf("%s p99 mismatch: BENCHMARKS.md says %.1f µs, measured.json says %.1f µs — regenerate the doc table and measured.json together (bench/regen.sh)", key, got, want)
		}
	}
}

// parseDocTableP99 pulls the p99 (5th data column) from each mode row of the
// distribution table. A row looks like:
//
//	| `balanced` | 1 + 2 heuristic (in-process) | 23.8 µs | 27.9 µs | 32.4 µs | ...
var floatRe = regexp.MustCompile(`[0-9]+\.[0-9]+`)

func parseDocTableP99(md string) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 6 {
			continue
		}
		var key string
		switch {
		case strings.Contains(cells[1], "fast"):
			key = "fast"
		case strings.Contains(cells[1], "balanced"):
			key = "balanced"
		case strings.Contains(cells[1], "comprehensive"):
			key = "comprehensive"
		default:
			continue
		}
		// cells: [ "", mode, stages, p50, p95, p99, max, mean, "" ] → p99 = cells[5]
		m := floatRe.FindString(cells[5])
		if m == "" {
			continue
		}
		v, _ := strconv.ParseFloat(m, 64)
		out[key] = v
	}
	return out
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
