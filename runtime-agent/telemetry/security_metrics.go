package telemetry

import (
	"sync"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
)

// SecurityActions is the bounded label vocabulary exported by /metrics.
// Unknown values are deliberately collapsed into "other" so an upstream value
// can never create unbounded Prometheus cardinality.
var SecurityActions = [...]string{
	"allowed",
	"blocked",
	"modified",
	"flagged",
	"escalated",
	"blocked_no_policy",
	"passthrough_no_policy",
	"blocked_stale_cache",
	"blocked_kill_switch",
	"passthrough_unknown_format",
	"other",
}

// FailOpenReasons is the bounded fail-open label vocabulary.
var FailOpenReasons = [...]string{
	"no_policy",
	"policy_stale",
	"stage2_unavailable",
	"stage3_unavailable",
	"unknown_format",
	"other",
}

// DurationBucketsMS are fixed millisecond buckets shared by total request and
// per-stage latency histograms. The largest bucket is five seconds; +Inf is
// always emitted separately.
var DurationBucketsMS = [...]float64{0.1, 0.5, 1, 5, 10, 50, 100, 500, 1000, 5000}

type durationHistogram struct {
	buckets [len(DurationBucketsMS)]uint64
	count   uint64
	sum     float64
}

func (h *durationHistogram) observe(valueMS float64) {
	if valueMS < 0 {
		valueMS = 0
	}
	for i, upper := range DurationBucketsMS {
		if valueMS <= upper {
			h.buckets[i]++
		}
	}
	h.count++
	h.sum += valueMS
}

// DurationSnapshot is an immutable histogram copy for Prometheus exposition.
type DurationSnapshot struct {
	Buckets [len(DurationBucketsMS)]uint64
	Count   uint64
	Sum     float64
}

// SecuritySnapshot is a bounded, immutable copy of agent security counters.
type SecuritySnapshot struct {
	Actions          [len(SecurityActions)]uint64
	FailOpen         [len(FailOpenReasons)]uint64
	StageUnavailable [2][2]uint64 // stage2/stage3 x open/closed
	RequestDuration  DurationSnapshot
	StageDuration    [3]DurationSnapshot // stage1/stage2/stage3
}

type securityMetrics struct {
	mu               sync.Mutex
	actions          [len(SecurityActions)]uint64
	failOpen         [len(FailOpenReasons)]uint64
	stageUnavailable [2][2]uint64
	requestDuration  durationHistogram
	stageDuration    [3]durationHistogram
}

func (m *securityMetrics) observe(event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.actions[actionIndex(string(event.ActionTaken))]++
	m.requestDuration.observe(float64(event.LatencyMS))

	if event.Stage1LatencyUS > 0 {
		m.stageDuration[0].observe(float64(event.Stage1LatencyUS) / 1000)
	}
	if event.Stage2LatencyUS != nil {
		m.stageDuration[1].observe(float64(*event.Stage2LatencyUS) / 1000)
	}
	if event.Stage3LatencyMS != nil {
		m.stageDuration[2].observe(float64(*event.Stage3LatencyMS))
	}

	switch event.ActionTaken {
	case policy.Action("passthrough_no_policy"):
		m.failOpen[failOpenIndex("no_policy")]++
	case policy.Action("passthrough_unknown_format"):
		m.failOpen[failOpenIndex("unknown_format")]++
	}

	behaviorIndex := 1 // closed
	if event.ActionTaken == policy.ActionAllowed {
		behaviorIndex = 0 // open
	}
	switch event.PipelineExitStage {
	case policy.ExitStage2Unavailable:
		m.stageUnavailable[0][behaviorIndex]++
		if behaviorIndex == 0 {
			m.failOpen[failOpenIndex("stage2_unavailable")]++
		}
	case policy.ExitStage3Unavailable:
		m.stageUnavailable[1][behaviorIndex]++
		if behaviorIndex == 0 {
			m.failOpen[failOpenIndex("stage3_unavailable")]++
		}
	}
}

func (m *securityMetrics) recordFailOpen(reason string) {
	m.mu.Lock()
	m.failOpen[failOpenIndex(reason)]++
	m.mu.Unlock()
}

func (m *securityMetrics) snapshot() SecuritySnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := SecuritySnapshot{
		Actions:          m.actions,
		FailOpen:         m.failOpen,
		StageUnavailable: m.stageUnavailable,
		RequestDuration:  snapshotHistogram(m.requestDuration),
	}
	for i, histogram := range m.stageDuration {
		out.StageDuration[i] = snapshotHistogram(histogram)
	}
	return out
}

func snapshotHistogram(histogram durationHistogram) DurationSnapshot {
	return DurationSnapshot{
		Buckets: histogram.buckets,
		Count:   histogram.count,
		Sum:     histogram.sum,
	}
}

func actionIndex(action string) int {
	for index, allowed := range SecurityActions[:len(SecurityActions)-1] {
		if action == allowed {
			return index
		}
	}
	return len(SecurityActions) - 1
}

func failOpenIndex(reason string) int {
	for index, allowed := range FailOpenReasons {
		if reason == allowed {
			return index
		}
	}
	// Collapse a future unknown reason into the final bounded label rather than
	// introducing cardinality.
	return len(FailOpenReasons) - 1
}
