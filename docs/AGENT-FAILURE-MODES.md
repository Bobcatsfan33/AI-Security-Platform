# Runtime-agent failure modes

What the inline agent does when a dependency fails — and the test that proves it.
This is half of the design-partner evidence pack (the other half is
[`BENCHMARKS.md`](BENCHMARKS.md)): an evaluator's second question, after "how
much latency does it add", is "what happens when something breaks". Every row
here is backed by an automated test, so the answer is evidence, not assertion.

The governing principle is **deny-by-default on a security surface**: where a
failure could either block traffic or let it pass uninspected, the *default*
resolves to blocking, and the operator opts into availability explicitly
(`fail_behavior: "open"` on a policy, or a recognised non-production
environment). A non-verdict is never labelled as a verdict — a stage that could
not answer says so (`Mode = *_unavailable`), so "allowed because it was clean"
and "allowed because the backend was down" are distinguishable in telemetry.

## The matrix

| Failure mode | Trigger | Observed behavior | Test | Operator guidance |
|---|---|---|---|---|
| **No policy at cold start** | Control plane unreachable at startup, nothing cached | `AGENT_NO_POLICY_BEHAVIOR` decides; **defaults to fail-CLOSED** in production (unset/unspecified env → closed). Both branches loud (`proxy_no_policy_fail_closed` / `_open`, distinct telemetry action). Unrecognised value = startup error, not a guess. | `proxy/nopolicy_test.go` | Deploy the control plane before/with the agent; a control-plane outage becomes a traffic outage by design (GAP-003). The retry/backoff contract is **not yet implemented** — see below. |
| **Stage 2 (ML sidecar) down** | ONNX sidecar unreachable / 5xx / timeout / malformed | Honors the policy's `fail_behavior`: blocks under `closed`, allows under `open`. Result carries `Mode = stage2_unavailable` — a down model is not a clean verdict (GAP-004). | `policy/stage2_failbehavior_test.go`, `policy/pipeline_stage2_unavailable_test.go` | Set `fail_behavior: "closed"` on policies where a missing ML opinion must not pass. Watch for `stage2_unavailable` in telemetry — it means `comprehensive` silently degraded. |
| **Stage 3 (LLM judge) down** | Judge endpoint unreachable / 5xx / timeout / malformed JSON | Honors `fail_behavior` (block/allow), and now carries `Mode = stage3_unavailable` vs `stage3_http` for a real ruling. **Fixed here:** the judge previously set no `Mode`, so a failed-open judge was indistinguishable from a clean one — the same honesty gap GAP-004 closed for Stage 2. | `policy/stage3_failbehavior_test.go` | Same as Stage 2. The judge only runs on an *uncertain* Stage-2 result under `comprehensive`, so its availability matters least, but a fail-open judge must still be visible. |
| **Kill switch activated mid-traffic** | Control plane sends `block_all` | The **next** request is blocked (451) — the check is a microsecond atomic gate *before* the policy pipeline, so it needs no cache refresh. `unblock_all` restores traffic immediately. Race-safe under concurrent flips. | `proxy/killswitch_proxy_test.go` | The emergency stop is immediate and reversible; it does not wait on policy propagation. (GAP-010: this path was previously untested.) |
| **Cert rotation mid-traffic** | Client cert files rewritten (cert-manager / installer cron) while the agent is making control-plane calls | Hot-reloaded on a timer under an `RWMutex`; a concurrent TLS handshake never observes a nil or torn certificate. No restart needed. | `internal/controlplane/client_test.go` (`TestCertReloaderPicksUpRotation`), `cert_rotation_concurrent_test.go` | Rotate freely; no coordination with the agent required. |
| **Malformed / erroring upstream RESPONSE** | Upstream returns garbage body, a 5xx, or is unreachable | A garbage body and a 5xx are **streamed through verbatim** (the upstream's output is the upstream's, not the agent's); an unreachable upstream yields **502**. The agent inspects the *request*, not the *response*. | `proxy/upstream_malformed_test.go` | **Stated scope decision:** the agent does NOT inspect or sanitize upstream responses today — response-side interception is a documented follow-on. If your threat model includes a compromised upstream returning malicious content, that is not covered by the inline agent yet. |
| **Redis policy-invalidation drop** | Redis blips; the pub/sub subscriber's channel closes | **Known gap (GAP-012, OPEN):** the subscriber returns and does not reconnect, so policy changes stop propagating until process restart — silently. The cached policy keeps serving (stale-but-connected-looking). | *(none yet)* | Restart the agent after a Redis outage to guarantee fresh policy propagation. Closed by the retry/backoff work — see below. |

## Deferred: the retry/backoff contract (Phase 2 increment 5)

Two related "the connection came back but we didn't" gaps remain, and they are
the subject of the next increment:

* **Cold-start policy load** (`cmd/agent/main.go`): the warm-load is a single
  attempt — on failure it logs and proceeds (governed by the no-policy behavior
  above). There is no bounded backoff retry for "agent up before control plane".
* **Redis subscriber reconnect** (GAP-012, the last row above): no reconnect loop.

Increment 5 lands a bounded exponential-backoff contract for both, documented
here alongside the fault-injection tests that verify it. Until then, treat deploy
ordering and post-Redis-outage restart as operator responsibilities — stated
plainly rather than papered over.

## How to reproduce

Every row's test runs in the standard suite:

```bash
cd runtime-agent && go test -race ./...
```

The failure-mode tests are ordinary Go tests (`*_failbehavior_test.go`,
`killswitch_proxy_test.go`, `upstream_malformed_test.go`,
`cert_rotation_concurrent_test.go`) — no sidecars or fixtures required; each
stands up its own mock backend with `httptest`.
