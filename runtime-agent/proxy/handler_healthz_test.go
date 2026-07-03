package proxy

import (
	"net/http/httptest"
	"testing"
)

// The SDKs (sdks/python/platform_sdk/_routing.py, sdks/node/src/routing.ts)
// probe GET {PLATFORM_AGENT_URL}/healthz on the PROXY port before routing
// LLM traffic through the agent. If this ever 404s again the SDKs silently
// fall back to direct, unprotected calls — pin the contract.
func TestHealthzServedOnProxyPort(t *testing.T) {
	h := Handler(Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /healthz on proxy handler = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}
