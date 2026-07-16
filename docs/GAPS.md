# Gaps

Seeded by the Phase 0 audit (see [`TIERS.md`](TIERS.md)). Guardrail 6: a gap
that cannot be closed here — because it needs real traffic, a third party, or a
product decision — is written down rather than papered over.

Each gap states what unblocks it. A gap with no unblock line is a wish.

Severity is about what a design partner discovers, not what is hard:
**P0** = a POC-killer or a security property we claim but cannot show;
**P1** = they will ask in the first month; **P2** = deferred with a trigger.

---

## P0 — all closed in Phase 1

Kept rather than deleted: what was wrong, and what closed it, is the useful
record. Phase 2 verifies the whole class under fault injection.

### GAP-005 — The SDK fail-closed branch is untested ✅ CLOSED (Phase 1)
**Was:** `PLATFORM_ENV=prod` makes both SDKs refuse to send LLM traffic when the
runtime agent is unreachable — the product's core promise — with **zero tests in
either language and no CI job**.
**Closed by:** `sdks/python/tests/test_routing.py` (38 tests) and
`sdks/node/src/routing.test.ts` (36 tests), covering the same contract case for
case so the two SDKs cannot drift apart; plus the `SDKs (fail-closed)` job in
`.github/workflows/ci.yml`, which is what makes them binding.
**Verified, not assumed:** both suites were mutation-tested — removing the
fail-closed default kills 8 Python tests and 7 Node tests. A suite that passes
against a broken implementation is decoration.

### GAP-003 — Agent cold start with no policy is unconditionally fail-open ✅ CLOSED (Phase 1)
**Was:** with no policy cached (control plane unreachable at startup) every
request passed uninspected. The code comment claimed "production deployments
configure fail-closed" for a setting that **did not exist**.
**Closed by:** `AGENT_NO_POLICY_BEHAVIOR` (`runtime-agent/proxy/nopolicy.go`),
mirroring the SDK convention so the platform documents one shape:

* explicit always wins;
* unset resolves by `AGENT_ENVIRONMENT` — production → closed, otherwise open;
* an *unspecified* environment resolves **closed** (absence of information is
  not evidence of a dev box);
* an unrecognised value is a **startup error**, not a fallback — the same
  refusal-to-guess as the agent's partial-mTLS check.

Both branches are loud: a log line (`proxy_no_policy_fail_closed` /
`proxy_no_policy_fail_open`, naming the `policy_id` to go fix) and a distinct
telemetry `ActionTaken` (`blocked_no_policy` / `passthrough_no_policy`).
Tested in `runtime-agent/proxy/nopolicy_test.go`.
**Note the behaviour change:** `AGENT_ENVIRONMENT` defaults to `production`, so
the agent now **fails closed on cold start by default**. That is deliberate
(guardrail 3) and it means **deploy ordering matters** — a control-plane outage
now becomes a traffic outage rather than a silent lapse in protection.
**Still open:** the retry/backoff contract for "agent up before control plane"
is undocumented. Phase 2 covers it in `docs/AGENT-FAILURE-MODES.md` and verifies
it under fault injection.

### GAP-004 — Stage 2 fail-open is hardcoded, ignoring `fail_behavior` ✅ CLOSED (Phase 1)
**Was:** `stage2_http.go` discarded the policy argument (`_ *CompiledPolicy`) and
returned fail-open on transport error, non-200 and decode error alike. A policy
with `fail_behavior: "closed"` **did not** make Stage 2 fail closed, and a down
ONNX sidecar was indistinguishable from a clean verdict (both `Matched:false`,
no `Mode` set), so `comprehensive` silently degraded to Stage-1-only.
**Closed by:** Stage 2 now honours `fail_behavior` exactly as Stage 3 does, via
a single `stage2Fail` exit mirroring `stage3Fail`. Every failure mode is
covered: unreachable, malformed response, 5xx, timeout.

The "unreachable vs clean" signal reuses the existing `Mode` honesty field
(`types.go`: *"names how the verdict was ACTUALLY computed"*) rather than
inventing a parallel mechanism — a real classification reports
`Mode=stage2_http`, a backend that never answered reports
`Mode=stage2_unavailable`. Same instinct as Stage 3's `"disabled"`: never label
a non-verdict as a verdict.
Tested in `runtime-agent/policy/stage2_failbehavior_test.go`.

---

## P1

### GAP-001 — Tier A blast radius and Tier B SIEM are unreachable
**What:** `api/v1/aibom.py` (3 endpoints, incl. the only blast-radius surface)
and `api/v1/siem.py` (4 endpoints, exporter CRUD) are on disk, tested at the
service layer, and **never mounted**. ~25 endpoints of working code
(also SCIM 13, idp_admin 5 — see GAP-009) are unreachable.
**Why it matters:** blast radius is a headline Tier A capability with no HTTP
surface. SIEM export is table stakes — a SOC that cannot see the platform's
events will not run it inline.
**Unblocks:** nothing external. **Phase 1** — mount both with full Tier A/B
test treatment. Blast radius needs a real endpoint, not just the scoring
factor. Deferred out of Phase 0 because mounting is a behaviour change.

### GAP-006 — Detection efficacy is entirely unmeasured
**What:** no efficacy suite for the attack graph or anomaly detector, no
false-positive budget published, and no scoring of the Stage 1+2 pipeline
against any public prompt-injection corpus. `/v1/benchmark` and `/v1/validation`
exist but score nothing external.
**Why it matters:** "behavioural anomaly detection" and "three-stage policy
pipeline" are the product. Right now their quality is an assertion. A design
partner's first question is "what is your false-positive rate?" and there is no
answer in the repo.
**Unblocks:** license-compatible public corpora (needs review before pinning).
Phases 1 and 3.

### GAP-002 — Agent latency is a target, not a measurement
**What:** `runtime-agent/README.md` presented "sub-15ms for `balanced` mode" as
a *binding architectural decision* justifying Go over Python. Nothing in the
repo measures latency: zero `Benchmark*` functions, no load test against the
proxy path. Corrected to "target, unmeasured" in Phase 0.
**Why it matters:** an inline proxy's added latency is the first number an
evaluator asks for, and the one that decides whether they run it inline at all.
**Unblocks:** nothing external. Phase 2 — `runtime-agent/bench/`, p50/p99 per
stage vs a mock upstream, results to `docs/BENCHMARKS.md`, CI regression gate.

### GAP-010 — `management` and `cmd/agent` are 0% covered
**What:** the kill switch (`management/killswitch.go`) has no test — the
block-all path at `handler.go:111` is never exercised. Heartbeat untested.
`KillSwitchState.Snapshot()` is documented as feeding `/metrics` but is never
called: dead code.
**Why it matters:** the kill switch is the control you demo to a security team.
**Unblocks:** nothing external. Phase 2.

### GAP-011 — `/metrics` has no security metrics
**What:** the agent's `/metrics` exposes six telemetry/uptime counters and
nothing about its actual function: no request/allow/block counters, no
per-stage latency histograms, no stage-error or fail-open counters, no
kill-switch gauge. Hand-rolled exposition with no `# HELP`/`# TYPE` headers.
**Why it matters:** you cannot currently observe from `/metrics` whether the
agent is blocking anything or whether Stage 2 is silently failing open
(GAP-004). An SRE cannot operate this.
**Unblocks:** nothing external. Phase 4.

### GAP-012 — Redis policy-invalidation subscriber never reconnects
**What:** [`cache.go:143`](../runtime-agent/policy/cache.go) returns on channel
close; [`main.go:187`](../runtime-agent/cmd/agent/main.go) logs
`policy_subscriber_exited` and never restarts it. After one Redis blip,
invalidation is dead for the life of the process — policy changes stop
propagating, silently, until restart.
**Why it matters:** a policy the operator believes they revoked stays live.
**Unblocks:** nothing external. Phase 2.

### GAP-007 — The CI/CD gate action is untested
**What:** [`actions/ai-security-gate/run.sh`](../actions/ai-security-gate/run.sh)
has zero tests, no shellcheck, and no CI job. Its only repo-wide reference
outside its own directory is a line in the README's layout tree.
**Unblocks:** nothing external. Phase 4.

### GAP-013 — 21 of 25 mounted routers have no HTTP-layer test
**What:** measured, not estimated: only `/connectors`, `/assets`, `/discovery`
and `/dashboard` are driven over HTTP by any test, and the same four are the
only ones with a cross-org isolation test. Service-level tests sit beneath the
router and exercise neither the request contract nor the auth/org-scoping
dependencies declared in the route signature — a service can be tenant-safe
while the route above it leaks.
**Why it matters:** guardrail 2 says every tenant-scoped surface proves a
sibling org cannot read it. Today, 4 do.
**Unblocks:** nothing external. Now ratcheted: the exemption list in
[`test_router_coverage_ratchet.py`](../backend/tests/unit/test_router_coverage_ratchet.py)
may only shrink, and each row names the phase that retires it.

---

## P2 — deferred, with triggers

### GAP-009 — SCIM + IdP admin are frozen
**What:** SCIM 2.0 (13 endpoints) and IdP admin (5) are built and unmounted.
**Trigger: promote before the first enterprise contract.** SCIM appears on
essentially every enterprise procurement questionnaire, but is irrelevant to a
90-day design-partner POC, where OIDC login (substrate, already working) is
sufficient. Spending Phase 1 hours here would buy nothing a partner will probe.

### GAP-008 — Two conflicting compliance framework lists
**What:** `/v1/compliance` offers `soc2 | iso27001 | fedramp_moderate`;
`reports.py:36` offers `soc2_ai | eu_ai_act | nist_ai_rmf | owasp_llm_top10`.
Two surfaces, two vocabularies, no mapping.
**Unblocks:** a product decision on which vocabulary is real. Phase 5.

### GAP-014 — `runtime-agent/README.md` is substantially stale
**What:** claims Stage 2, Stage 3, kill switch and heartbeat are "⏸️ follow-on"
— all four are implemented. Describes Stage 2 as "Rust+CGo ONNX" (it is an HTTP
sidecar) and the kill switch as "via WebSocket" (it is HTTP long-poll). The
latency claim was corrected in Phase 0 (GAP-002); the rest remains.
**Unblocks:** nothing external. Phase 5 rewrites it.

### GAP-016 — Local gates are not CI gates: dependencies are unpinned
**What:** `backend/pyproject.toml` pins loose lower bounds, so a local venv and
a fresh CI install resolve **different major versions**. Found the hard way in
Phase 0: locally `fastapi==0.136.1`, CI resolved `0.139.2`, and the Phase 0
tier tests passed locally and failed on CI.

The behaviour that differed is instructive — FastAPI 0.139 made
`include_router` *lazy*, appending an internal `_IncludedRouter` placeholder
instead of flattening `APIRoute` objects into `app.routes`. Routing works
identically; only introspection changed. So the app was fine and the *tests*
were wrong, which is the expensive kind of failure: CI was right, and there was
no local way to discover it.
**Why it matters:** guardrail 4 says "full test suite green before every
commit", and that is worth less than it appears when the local suite and the CI
suite are running against different libraries. Every future phase pays this tax.
Secondary: an unpinned transitive upgrade can change runtime behaviour in
production with no diff to review.
**Unblocks:** nothing external. Needs a product decision on approach — a lock
file (`pip-compile` / `uv lock`) committed and installed with `--require-hashes`
in CI is the honest fix; pinning only the direct deps in `pyproject.toml` is the
cheap one and leaves transitives free. Recommend the lock file. Phase 4
(operability) unless it bites again first.
**Mitigation now:** the tier tests were rewritten to assert against the OpenAPI
schema — the published contract — rather than FastAPI's internal route storage,
and verified green against **both** 0.136.1 and 0.139.2. That makes this
particular test version-robust; it does not fix the class.

### GAP-015 — No frontend test infrastructure
**What:** zero tests, no runner, no `test` script. `next build` is the only
frontend CI gate. Also 7 copy-pasted `SeverityBadge` definitions and no shared
component library (Phase 0 added the first shared component, `PreviewBadge`).
**Why it matters:** Phase 1 brings the MCP and anomalies pages to backend
parity with no regression net under them.
**Unblocks:** nothing external. Phase 1 stands up a runner.

---

## External gates (cannot be closed in this repo)

Carried forward from the README's honest-status section. None of these is
engineering work; listing them here keeps them from being quietly forgotten.

| Gate | What unblocks it |
|---|---|
| Independent security audit / pen test | A third-party firm. Not scheduled. |
| Stage-2 ONNX model artifact | An operator runs `scripts/export_stage2_onnx.py`, cuts a release, pins the SHA. Until then Stage 2 runs the honest heuristic fallback. |
| SOC 2 Type II | Evidence mapping is done; the observation window has not started. |
| HA/DR validation | `docs/HA-DR-RUNBOOK.md` is self-labelled scaffolding, not validated. Needs real infrastructure. |
| Production deployments / reference customers | None yet. This is what the design-partner POC is for. |
| Second maintainer / branch protection | Single maintainer; `scripts/org/protect.sh` exists but enabling protection would block all merges. |
