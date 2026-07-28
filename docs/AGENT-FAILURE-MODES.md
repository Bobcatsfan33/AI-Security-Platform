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
| **No policy at cold start** | Control plane unreachable at startup, nothing cached | The warm load retries with **bounded, jittered exponential backoff** (`LoadWithRetry`); on give-up it PROCEEDS to `AGENT_NO_POLICY_BEHAVIOR`, which **defaults to fail-CLOSED** in production. **Backoff-then-proceed, never backoff-forever:** the agent always starts, and a control plane that never comes up means fail-closed (safe) traffic, not a hung process. Both no-policy branches loud (`proxy_no_policy_fail_closed` / `_open`); an unrecognised env value is a startup error, not a guess. | `proxy/nopolicy_test.go`, `policy/cache_retry_test.go` (`TestLoadWithRetry*`) | Deploy ordering is now forgiving — a briefly-late control plane is absorbed by the backoff; a permanently-absent one fails closed (GAP-003). |
| **Stage 2 (ML sidecar) down** | ONNX sidecar unreachable / 5xx / timeout / malformed | Honors the policy's `fail_behavior`: blocks under `closed`, allows under `open`. Result carries `Mode = stage2_unavailable` — a down model is not a clean verdict (GAP-004). | `policy/stage2_failbehavior_test.go`, `policy/pipeline_stage2_unavailable_test.go` | Set `fail_behavior: "closed"` on policies where a missing ML opinion must not pass. Watch for `stage2_unavailable` in telemetry — it means `comprehensive` silently degraded. |
| **Stage 3 (LLM judge) down** | Judge endpoint unreachable / 5xx / timeout / malformed JSON, in both fail directions | Honors `fail_behavior` (block/allow). **Fully mirrors the Stage-2 honesty fix (GAP-004):** the result carries `Mode = stage3_unavailable` (vs `stage3_http` for a real ruling), the pipeline takes an explicit `ExitStage3Unavailable` exit for BOTH behaviours (not `ExitStage3Judge` on a fail-closed block, not `ExitNoMatch` on a fail-open allow), and it emits **no** `MatchedRules` entry — a judge that never answered fired no rule. Before this, the judge set none of the three. | `policy/stage3_failbehavior_test.go`, `policy/pipeline_stage3_unavailable_test.go` | Same as Stage 2. The judge only runs on an *uncertain* Stage-2 result under `comprehensive`, so its availability matters least, but a fail-open judge must still be visible. |
| **Kill switch activated mid-traffic** | Control plane sends `block_all` | The **next** request is blocked (451) — the check is a microsecond atomic gate *before* the policy pipeline, so it needs no cache refresh. `unblock_all` restores traffic immediately. Race-safe under concurrent flips. | `proxy/killswitch_proxy_test.go` | The emergency stop is immediate and reversible; it does not wait on policy propagation. (GAP-010: this path was previously untested.) |
| **Cert rotation mid-traffic** | Client cert files rewritten (cert-manager / installer cron) while the agent is making control-plane calls | Hot-reloaded on a timer under an `RWMutex`; a concurrent TLS handshake never observes a nil or torn certificate. No restart needed. | `internal/controlplane/client_test.go` (`TestCertReloaderPicksUpRotation`), `cert_rotation_concurrent_test.go` | Rotate freely; no coordination with the agent required. |
| **Malformed / erroring upstream RESPONSE** | Upstream returns garbage body, a 5xx, or is unreachable | A garbage body and a 5xx are **streamed through verbatim** (the upstream's output is the upstream's, not the agent's); an unreachable upstream yields **502**. The agent inspects the *request*, not the *response*. | `proxy/upstream_malformed_test.go` | **Stated scope decision:** the agent does NOT inspect or sanitize upstream responses today — response-side interception is a documented follow-on. If your threat model includes a compromised upstream returning malicious content, that is not covered by the inline agent yet. |
| **Redis policy-invalidation drop** | Redis blips; the pub/sub subscriber's channel closes | Reconnects with jittered backoff, forever, and **re-fetches the policy on every reconnect** — so any invalidation missed while deaf is caught up (GAP-012 closed). The distinct hazard here was staleness, not disconnection: a reconnected subscriber that didn't re-fetch would keep serving what it cached when it went deaf while looking healthy. Staleness is also independently visible (`LoadedAt`/`IsStale`, emitted in the heartbeat). | `policy/cache_retry_test.go` (`TestReconnectLoopRefetchesAndStops`) | No action needed across a Redis outage — the agent self-heals and catches up. |

## Retry / backoff: the whole class, enumerated

The retry/backoff contract now exists (Phase 2 increment 5) — one jittered,
capped primitive (`internal/backoff`) shared by the two paths that gave up too
early. Rather than fix only those two, here is **every** retry-or-give-up path in
the agent, with its status, so the class is enumerated even where nothing changed:

| Path | Behavior | Status |
|---|---|---|
| Cold-start policy load (`cmd/agent`) | Was single-attempt; now bounded backoff → proceed to fail-closed | **Fixed (inc 5)** |
| Redis invalidation subscriber (`policy/cache.go`) | Was single-attempt; now unbounded reconnect + re-fetch | **Fixed (inc 5), GAP-012 closed** |
| Kill-switch poller (`management/killswitch.go`) | Loops forever, fixed 5 s cadence on error | **Already covered** — and deliberately fixed-cadence, not exponential: you do not back off from the emergency-stop channel. |
| Heartbeat (`management/heartbeat.go`) | Ticker loop; a missed beat self-heals next interval | **Already covered** (periodic retry) |
| Telemetry uploader (`telemetry/buffer.go`) | Drops a failed batch and counts it | **Best-effort by design** — telemetry loss is not a security failure; retrying it would risk memory growth under a sustained outage. Intentional, not a gap. |

**The two fixes' distinct give-up policies** (the abstraction is shared; the
policy is not): cold-start is **bounded** (it must proceed to
`AGENT_NO_POLICY_BEHAVIOR`), the reconnect loop is **unbounded** (a subscriber
that gives up is a silently-stale policy). And the reconnect loop adds
**re-fetch-on-reconnect** — reconnection alone would leave the staleness hazard
open.

## How to reproduce

Every row's test runs in the standard suite:

```bash
cd runtime-agent && go test -race ./...
```

The failure-mode tests are ordinary Go tests (`*_failbehavior_test.go`,
`killswitch_proxy_test.go`, `upstream_malformed_test.go`,
`cert_rotation_concurrent_test.go`) — no sidecars or fixtures required; each
stands up its own mock backend with `httptest`.
