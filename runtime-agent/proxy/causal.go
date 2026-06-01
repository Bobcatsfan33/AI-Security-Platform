package proxy

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Causal-lineage propagation headers. Wire-compatible with the Python
// control plane (backend/app/telemetry/causal.py). We carry lineage two
// ways: W3C traceparent for interop with existing tracing infrastructure
// (trace-id == poset root_event_id), and the native x-aisp-* headers which
// round-trip the full 128-bit event UUIDs that traceparent's 64-bit
// span-id cannot.
const (
	HeaderTraceparent  = "traceparent"
	HeaderRoot         = "X-Aisp-Root-Event"
	HeaderParent       = "X-Aisp-Parent-Event"
	HeaderCorrelation  = "X-Aisp-Correlation-Key"
	HeaderDepth        = "X-Aisp-Causal-Depth"
	traceparentVersion = "00"
	traceparentFlags   = "01"
)

// CausalContext is the lineage threaded between two causally-linked events.
type CausalContext struct {
	RootEventID    uuid.UUID
	ParentEventID  uuid.UUID
	CorrelationKey string
	CausalDepth    int
}

// Traceparent renders the context as a W3C traceparent header value.
// trace-id <- root_event_id (128-bit); span-id <- low 64 bits of the
// parent event id (lossy by spec — the native header carries the full id).
func (c CausalContext) Traceparent() string {
	traceID := strings.ReplaceAll(c.RootEventID.String(), "-", "")
	low := c.ParentEventID[8:16] // low 64 bits of the UUID
	return fmt.Sprintf("%s-%s-%x-%s", traceparentVersion, traceID, low, traceparentFlags)
}

// Apply writes the propagation headers onto an outbound request so the
// next hop inherits the lineage.
func (c CausalContext) Apply(h http.Header) {
	h.Set(HeaderTraceparent, c.Traceparent())
	h.Set(HeaderRoot, c.RootEventID.String())
	h.Set(HeaderParent, c.ParentEventID.String())
	h.Set(HeaderCorrelation, c.CorrelationKey)
	h.Set(HeaderDepth, strconv.Itoa(c.CausalDepth))
}

// ParseTraceparent extracts the root_event_id (trace-id) from a traceparent
// value. Returns ok=false on a malformed header — propagation is
// best-effort and must never break the request.
func ParseTraceparent(value string) (uuid.UUID, bool) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 || len(parts[1]) != 32 {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// CausalFromHeaders reconstructs a CausalContext from inbound request
// headers. Prefers the high-fidelity native headers; falls back to
// traceparent for the root id. Returns ok=false when there is no usable
// lineage (the caller then treats the event as a fresh root).
func CausalFromHeaders(h http.Header) (CausalContext, bool) {
	var root uuid.UUID
	if rawRoot := h.Get(HeaderRoot); rawRoot != "" {
		if id, err := uuid.Parse(rawRoot); err == nil {
			root = id
		}
	}
	if root == uuid.Nil {
		if id, ok := ParseTraceparent(h.Get(HeaderTraceparent)); ok {
			root = id
		}
	}
	if root == uuid.Nil {
		return CausalContext{}, false
	}

	// Without a parent there is no causal edge to draw.
	parent, err := uuid.Parse(h.Get(HeaderParent))
	if err != nil {
		return CausalContext{}, false
	}

	depth := 0
	if d, err := strconv.Atoi(h.Get(HeaderDepth)); err == nil && d >= 0 {
		depth = d
	}

	correlation := h.Get(HeaderCorrelation)
	if correlation == "" {
		correlation = root.String()
	}

	return CausalContext{
		RootEventID:    root,
		ParentEventID:  parent,
		CorrelationKey: correlation,
		CausalDepth:    depth,
	}, true
}

// StampEvent copies the lineage from an inbound CausalContext onto a
// telemetry event. The event represents the current hop, so its causal
// depth is the inbound depth plus one (the inbound context describes the
// PARENT). When ok is false the event is left as a root and the caller's
// NewEvent-assigned EventID becomes the poset root downstream.
func ApplyCausalToEventFields(ctx CausalContext, ok bool) (root, parent, corr string, depth uint16) {
	if !ok {
		return "", "", "", 0
	}
	return ctx.RootEventID.String(),
		ctx.ParentEventID.String(),
		ctx.CorrelationKey,
		uint16(ctx.CausalDepth + 1)
}
