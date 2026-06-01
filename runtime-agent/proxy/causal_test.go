package proxy

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestTraceparentRoundTrip(t *testing.T) {
	ctx := CausalContext{
		RootEventID:    uuid.New(),
		ParentEventID:  uuid.New(),
		CorrelationKey: "task-9",
		CausalDepth:    2,
	}
	tp := ctx.Traceparent()
	got, ok := ParseTraceparent(tp)
	if !ok {
		t.Fatalf("ParseTraceparent(%q) returned ok=false", tp)
	}
	if got != ctx.RootEventID {
		t.Errorf("trace-id round-trip: got %v, want %v", got, ctx.RootEventID)
	}
}

func TestParseTraceparentMalformed(t *testing.T) {
	cases := []string{"garbage", "00-tooshort-aaaa-01", "", "00-x-y"}
	for _, c := range cases {
		if _, ok := ParseTraceparent(c); ok {
			t.Errorf("ParseTraceparent(%q) = ok, want malformed", c)
		}
	}
}

func TestCausalFromHeadersNativeFidelity(t *testing.T) {
	ctx := CausalContext{
		RootEventID:    uuid.New(),
		ParentEventID:  uuid.New(),
		CorrelationKey: "task-9",
		CausalDepth:    3,
	}
	h := http.Header{}
	ctx.Apply(h)

	got, ok := CausalFromHeaders(h)
	if !ok {
		t.Fatal("CausalFromHeaders returned ok=false on a fully-stamped request")
	}
	if got.RootEventID != ctx.RootEventID || got.ParentEventID != ctx.ParentEventID {
		t.Errorf("ids: got %+v, want %+v", got, ctx)
	}
	if got.CorrelationKey != ctx.CorrelationKey || got.CausalDepth != ctx.CausalDepth {
		t.Errorf("meta: got %+v, want %+v", got, ctx)
	}
}

func TestCausalFromHeadersNoLineage(t *testing.T) {
	if _, ok := CausalFromHeaders(http.Header{}); ok {
		t.Error("empty headers should yield ok=false (fresh root)")
	}
}

func TestCausalFromHeadersTraceparentOnlyNoParent(t *testing.T) {
	// traceparent present but our native parent header dropped → no edge.
	ctx := CausalContext{RootEventID: uuid.New(), ParentEventID: uuid.New()}
	h := http.Header{}
	h.Set(HeaderTraceparent, ctx.Traceparent())
	if _, ok := CausalFromHeaders(h); ok {
		t.Error("traceparent without native parent should yield ok=false")
	}
}

func TestApplyCausalToEventFieldsIncrementsDepth(t *testing.T) {
	ctx := CausalContext{
		RootEventID:    uuid.New(),
		ParentEventID:  uuid.New(),
		CorrelationKey: "k",
		CausalDepth:    2,
	}
	root, parent, corr, depth := ApplyCausalToEventFields(ctx, true)
	if depth != 3 {
		t.Errorf("depth: got %d, want 3 (inbound+1)", depth)
	}
	if root != ctx.RootEventID.String() || parent != ctx.ParentEventID.String() || corr != "k" {
		t.Errorf("fields mismatch: %s %s %s", root, parent, corr)
	}

	// Not-ok → fresh root (empty lineage).
	r, p, c, d := ApplyCausalToEventFields(ctx, false)
	if r != "" || p != "" || c != "" || d != 0 {
		t.Errorf("not-ok should yield empty lineage, got %q %q %q %d", r, p, c, d)
	}
}
