package proxy

import (
	"fmt"
	"strings"
)

// NoPolicyBehavior decides what the proxy does when it has NO policy at all —
// the cold-start case where the control plane was unreachable and the cache is
// empty.
//
// This is distinct from a policy's own `fail_behavior`, which governs what
// happens when a *stage* cannot reach its backend. Here there is no policy to
// read a fail_behavior from, which is exactly why this needed its own setting:
// before it existed, the proxy forwarded every request uninspected and the code
// comment pointed at a "production deployments configure fail-closed" knob that
// was never built.
//
// The resolution mirrors the SDKs' convention (sdks/python/platform_sdk/_routing.py,
// sdks/node/src/routing.ts) so the platform has ONE shape to document:
//
//	explicit setting always wins;
//	unset → resolve by environment (production → closed, otherwise open).
//
// The trade-off is real and belongs to the operator: fail-closed on cold start
// turns a control-plane outage into a customer-traffic outage, so deploy
// ordering matters (bring the control plane up first, or accept the agent's
// retry window). docs/AGENT-FAILURE-MODES.md carries the retry/backoff story.
// Defaulting the other way would mean a platform whose central promise silently
// lapses at exactly the moment it is most needed.
type NoPolicyBehavior string

const (
	// NoPolicyOpen forwards uninspected. Never silent — the proxy logs and
	// emits telemetry on every request that takes this path.
	NoPolicyOpen NoPolicyBehavior = "open"
	// NoPolicyClosed refuses with 451.
	NoPolicyClosed NoPolicyBehavior = "closed"
)

// Environment values that mean "production" for the purpose of the default.
// Matches the SDKs' prod/production pair.
var productionEnvironments = map[string]bool{"prod": true, "production": true}

// ResolveNoPolicyBehavior turns AGENT_NO_POLICY_BEHAVIOR + AGENT_ENVIRONMENT
// into a decision.
//
// An unrecognised explicit value is an error rather than a fallback: the agent
// already refuses to start on partially-configured mTLS instead of silently
// downgrading (cmd/agent), and a security setting that quietly ignores a typo
// is the same class of bug. Callers are expected to treat the error as fatal at
// startup, not to paper over it at request time.
func ResolveNoPolicyBehavior(explicit, environment string) (NoPolicyBehavior, error) {
	switch strings.ToLower(strings.TrimSpace(explicit)) {
	case string(NoPolicyOpen):
		return NoPolicyOpen, nil
	case string(NoPolicyClosed):
		return NoPolicyClosed, nil
	case "":
		// Unset — resolve by environment.
		env := strings.ToLower(strings.TrimSpace(environment))
		if env == "" || productionEnvironments[env] {
			// An UNSPECIFIED environment resolves closed, not open. Absence of
			// information is not evidence of a dev box: only a deliberately
			// named non-production environment buys the permissive branch.
			// (cmd/agent defaults AGENT_ENVIRONMENT to "production" anyway, so
			// this is belt-and-braces for any other caller.)
			return NoPolicyClosed, nil
		}
		return NoPolicyOpen, nil
	default:
		return "", fmt.Errorf(
			"AGENT_NO_POLICY_BEHAVIOR=%q is not valid: want %q or %q (unset resolves by "+
				"AGENT_ENVIRONMENT: production → %q, otherwise → %q)",
			explicit, NoPolicyOpen, NoPolicyClosed, NoPolicyClosed, NoPolicyOpen,
		)
	}
}
