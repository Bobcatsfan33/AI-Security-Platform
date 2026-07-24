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
**Closed by:** `sdks/python/tests/test_routing.py` and
`sdks/node/src/routing.test.ts`, both iterating ONE shared decision table
(`sdks/routing-cases.json`) so a case added for either language is demanded of
the other; plus the `SDKs (fail-closed)` CI job, which is what makes them
binding.
**Verified mechanically, not in prose:** `sdks/mutation_check.sh` runs in CI. It
reintroduces the exact regression — the permissive default — and fails the build
if either suite stays green against it. A hand-run mutation is a claim about a
moment; this is the repo's rule (a claim points at something checked) applied to
the test suite itself.

**BEHAVIOUR CHANGE — unset `PLATFORM_ENV` now fails closed.** Review of the
first cut caught that the SDKs fell back to unprotected direct calls on
unset/empty/unrecognised `PLATFORM_ENV`, while the agent resolved unset to
closed. The "one convention" claim was therefore false at its most dangerous
edge: **a production deployment that simply forgot to set `PLATFORM_ENV` shipped
unprotected traffic behind a warning** — permissive by doing nothing. Both SDKs
now match the agent: explicit `PLATFORM_FALLBACK_DIRECT` always wins; otherwise
only a *recognised* non-production environment (an allowlist, so
`PLATFORM_ENV=porduction` fails closed rather than reading as "not production")
buys the fallback. The refusal names `PLATFORM_ENV=development`,
`PLATFORM_AGENT_URL` and `PLATFORM_FALLBACK_DIRECT` verbatim, because this trips
first-run developers — one line of friction, once, against silent unprotected
prod traffic. Documented in `sdks/python/README.md` and `sdks/node/README.md`
(both new — the SDKs had no README at all, despite `package.json` listing one).

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

### GAP-001 — Tier A blast radius and Tier B SIEM are unreachable — ✅ DONE (SIEM + aibom mounted)
**What:** `api/v1/aibom.py` (3 endpoints, incl. the only blast-radius surface)
and `api/v1/siem.py` (4 endpoints, exporter CRUD) were on disk and **never
mounted**. SIEM export is table stakes — a SOC that cannot see the platform's
events will not run it inline — and blast radius is a headline Tier A capability
with no HTTP surface.

**SIEM ✅ mounted (Tier B):** `/v1/siem` reachable, with HTTP + tenant-isolation
tests through the mounted app (not a bare APIRouter) plus the validator unit
tests. First surface to exercise the tier registry end to end, and the ratchet's
first live test — mounting demanded HTTP + isolation tests before it would go
green. Added `RouterSpec.user_facing` for it: admin-only APIs are Tier B (their
API is preview-tagged) but have no page to badge, so they are excluded from the
frontend parity list.

Review of the mount caught **F1: the send path never resolved secret refs** —
`_build_one` handed the stored `env:TOKEN` string straight to the exporter, so a
real Splunk received the literal ref as its auth header. The "usable out of the
box" pair could not authenticate. Fixed: refs resolve at the build chokepoint
(`_resolve_secret_refs`), the stored JSONB keeps the ref, and an unresolvable
ref drops that one exporter loudly rather than raising — a rotated secret cannot
silence the whole forwarder. Same lesson as aibom: the audit graded
reachability, not function.

**aibom ✅ mounted (Tier A):** the audit missed that the router did not work
against the current model — `_asset_to_dict` read ~30 attributes the v2.0 pivot
removed from `AIAsset` (now a `metadata_json` bag), so it would `AttributeError`
on the first request; it also had zero tests. Fixed: `_asset_to_dict` reads
`metadata_json` **verbatim, no defaults** (permissive-when-missing — a sparse
asset yields honest-empty, never a fabricated value), and `app/aibom/blast_radius.py`
computes the blast radius as a reachability decomposition (downstream fan-out,
external-action surface, tool/MCP reach, autonomy, exposure, data sensitivity),
not the stored scalar. Two guaranteed properties, tested: **honest-when-thin**
(a metadata-less asset is low-radius with factors that STATE the absence — the
reasons are the product) and **deterministic** (same row → byte-identical
decomposition; no clock, no dict-ordering). Function was proven against a real
asset row (real JSONB round-trip) BEFORE the mount, then mounted Tier A with
HTTP + tenant-isolation tests through `create_app`. First Tier A mount — no
preview tag, the reference-quality bar.

**Lesson the SIEM mount taught (applies to aibom):** Phase 0's audit graded
*reachability*, not *function*. It called aibom "3 endpoints" and SIEM "4
endpoints, exporter CRUD" — both accurate about what was on disk, both wrong
about whether it worked. SIEM's send path never resolved secret refs (F1 below);
aibom's router doesn't survive contact with the model. So for aibom the bar is:
**prove the endpoints work against the CURRENT model with integration tests
before mounting, not after.**

### GAP-018 — SIEM exporter config: residual hardening (post-mount)
The mount closed the load-bearing defects (F1 secret resolution on the send
path; the write-path gate; redaction that no longer leaks a mis-named secret
key). These remain, none blocking a design-partner POC that uses Splunk/Elastic
with env-var refs:

* **N1 — dead secret fields ✅ CLOSED.** `SECRET_CONFIG_FIELDS["elastic"]` named
  `basic_auth_password`, but `ElasticExporter` took a `basic_auth` tuple — no
  such parameter — so a config using the declared field resolved its secret,
  then TypeError'd at build and was dropped, while the field the constructor
  actually accepted was neither validated nor redacted (a raw password there was
  stored in the clear and echoed on read). `webhook`'s `bearer_token` was dead
  the same way. Fixed: both constructors now accept the declared scalar field
  (`basic_auth_user`/`basic_auth_password`; `bearer_token`), `auth` was added to
  the redaction patterns, and `test_siem_secret_field_integrity.py` is the
  ratchet — every `SECRET_CONFIG_FIELDS` entry must name a real constructor
  parameter and be redactable, so the next dead-field drift fails a test.
* **F2 (partial) — redaction is a deny-list, not an allow-list.** `_redact` now
  masks known secret fields *plus* any key whose name reads as a secret
  (`token`, `password`, `bearer`, …), so the reported `token_ref` leak is
  closed. But a secret stored under a genuinely innocuous key name still shows.
  The fail-safe form is allow-list redaction — show only keys known to be
  non-secret, mask everything else — which needs the safe-key set enumerated per
  exporter type. Deferred; the deny-list closes the reported cases.
* **F3 — webhook (Tier C) headers can carry raw credentials.** `bearer_token` is
  now a real, resolved, redacted field (see N1), but an operator who instead
  puts `Authorization` inside the `headers` **map** bypasses validation and
  redaction: the top-level key is `headers` (matches no pattern), and the secret
  is a nested value the scalar-field mechanism does not reach. Flag-gated
  (`PLATFORM_ENABLE_SIEM_EXTENDED`, off by default), so not reachable on a
  default deployment, but it must be closed before webhook is promoted out of
  Tier C — nested resolution/redaction, or a rule that forbids raw
  `Authorization` in `headers`.
* **F5 — no config-shape validation on create, and denied attempts are not
  audit-logged.** A Splunk config missing `url` is accepted, then silently
  dropped at build (`TypeError` → the operator learns from absent events, not an
  error). And `log_event(...SUCCESS)` fires only on the happy path — a denied
  create/update (gated type, unresolvable secret, tier violation) writes no
  audit record, which is half an audit on a security surface. Both want a
  per-type required-config schema and an audit-on-denial pass.

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

### GAP-016 — Local gates are not CI gates: dependencies are unpinned ✅ CLOSED
**Was:** `pyproject.toml` pinned loose lower bounds, so a local venv and a fresh
CI install resolved **different major versions**. Found the hard way: locally
`fastapi==0.136.1`, CI `0.139.2`, and 0.139 had made `include_router` lazy.
Routing was identical — only introspection changed — so the app was fine and the
*tests* were wrong. CI was right and there was no local way to discover it.
Guardrail 4 ("full suite green before every commit") is worth little while the
two suites run against different libraries.

**Closed by** two hashed, universal locks generated from one pyproject by
`scripts/lock.sh`, and installed with `--require-hashes` everywhere:

| Lock | Extras | Pkgs | Installed by |
|---|---|---|---|
| `requirements.lock` | `--all-extras` | 100 | CI, developers |
| `requirements-runtime.lock` | none | 75 | **the production image** |

The split is not tidiness: `backend/Dockerfile`'s runtime stage does
`COPY --from=builder /install /usr/local`, so anything installed in the builder
reaches the shipped image. The all-extras lock would put pytest, ruff, mypy and
bandit in production — inflating what the A-2 hardening shrank and handing Trivy
25 extra packages to find CVEs in. The runtime lock is `--constraint`ed to the
full lock so the two agree **version for version**: the first cut of the split
had CI testing `huggingface-hub` 1.23.0 while the image shipped 1.24.0 (a dev
extra held the shared transitive back), which is this very gap reintroduced one
level down. Caught by `test_dependency_locks.py`, which now guards it.

**The Dockerfile was the last hole, and the worst one.** GAP-016 originally
pinned CI and dev while the image still did `pip install .` — a floating
resolution — and *that image* is what `security.yml` Trivy-scans, SBOM-attests
and cosign-signs. The pinning claim was loudest about the one artifact it did
not cover: no number of signatures makes an SBOM describe something
reproducible when the contents were decided by whatever PyPI served that
afternoon. Now fixed, and asserted by a test that reads the Dockerfile.

Determinism is a property of the *invocation*, learned twice: `--python-version`
is pinned to the `requires-python` floor (uv annotates `# via` comments from the
running interpreter's markers, so macOS/3.14 and CI/3.12 produced different
bytes from an identical resolution), and CI's drift check **runs `lock.sh`
itself** rather than reimplementing the command (uv embeds the verbatim command
line, including `-o`, in the file header — so compiling to any other path
guarantees a diff on line 2 forever).

**What this does NOT cover** — stated plainly, because the value of the lock is
exactly its honesty:

* **Dependabot does not maintain these locks.** It bumps direct deps in
  `pyproject.toml`; those PRs arrive **red** on the sync check until someone runs
  `lock.sh` (an acceptable forcing function, but it means zero auto-merge). More
  importantly it files **nothing** for transitive-only CVEs — the common case,
  and one this repo has already lived through twice with starlette-via-fastapi.
  **`pip-audit` in CI is the sole transitive signal.** "Dependabot covers pip"
  would imply more than is true.
* **Build-backend deps are still unpinned.** `pip install --no-deps .` uses PEP
  517 build isolation, which fetches `setuptools`/`wheel` (from
  `[build-system] requires`) at build time with no hashes. Smaller hole than the
  runtime tree, but it is in the image build. Fix is `--no-build-isolation` plus
  pinned build deps; not attempted here because it cannot be verified without a
  local Docker.
* **Not everything at build time is pinned.** uv is version-pinned (and
  `lock.sh` now *enforces* the pin rather than naming it, since uv's output
  format is version-dependent), but not hash-pinned; `pip` and `pip-audit` are
  unpinned. Consistent with the repo's existing patterns, and not a claim of
  literal supply-chain purity.
* **`sdks/python` CI still installs `-e ".[dev]"` unpinned** — the same bug
  class, one directory over. See GAP-017.

**Frontend npm-audit policy (the other half of the transitive story).** A
Next.js app accretes transitive advisories that land continuously in the
advisory DB — libvips via `sharp`, `@babel/core`, `postcss` — and a plain
`npm audit --audit-level=high` gate blocks **every** PR the moment one is
disclosed, for reasons unrelated to the change (this happened twice in one
afternoon during GAP-001). The response is **not** to weaken the gate:

* **The gate stays blocking. It never goes warn-only.** `frontend/scripts/audit-gate.mjs`
  fails the build on any high/critical advisory.
* **Exceptions are time-boxed, owned, and justified — not ignores.** A
  non-expired entry in `frontend/audit-exceptions.json` (advisory id, an
  exposure-grounded justification, an owner, an expiry) may defer a **dev,
  build-chain, or optional-and-unused** advisory. Expiry is 30 days default,
  90 max.
* **A production-artifact advisory gets NO exception** — the
  `--omit=dev --omit=optional` closure is the hard bar. It ships in the signed
  image; it must be fixed.
* **An expired exception is a RED gate**, enforced both by the gate script and
  by `test_audit_exceptions.py` (which fails `pytest` the day an exception
  lapses) — the debt is revisited on a clock, never forgotten.
* Current sole exception: `sharp` (GHSA-f88m-g3jw-g9cj). `next/image` is unused,
  `images.unoptimized` stops Next invoking it, and `outputFileTracingExcludes`
  drops it from the `.next/standalone` bundle — verified absent from the build,
  so it is not in the signed image. It cannot be dropped from the dev install
  (`npm --omit=optional` also removes Tailwind's `lightningcss` and Next's SWC
  natives), which is why the audit still sees it. Retire when Next ships a
  patched sharp.

Dependabot (npm, frontend + Node SDK) is the mechanism that actually *moves*
these; the audit gate is the backstop that fails the build if one lands with no
non-breaking fix, and the exception file is how such a case is deferred honestly
rather than by turning the gate off.

**Worked example — the hard bar held on first contact (2026-07-23, PR #89).**
A batch of Next.js advisories disclosed that morning turned both frontend gates
red on every open PR at once: five `next`/`postcss` advisories on the npm gate
and four HIGH `next` CVEs on the Trivy image gate. Every one was a **production**
dependency advisory with a **fixed version available** — exactly the class the
policy says gets *no* exception. The gate offered no deferral and none was taken:
`next` 16.2.6→16.2.11 plus a `postcss`→8.5.22 override, fixed not deferred, in a
standalone two-file PR that merged before the feature work rebased onto it. The
`sharp` entry stayed the *only* exception — the one advisory that is genuinely
unfixable-by-us and verified absent from the shipped bundle. This is the ledger
working as designed: an exception is the rare, justified case, not the escape
hatch every red advisory reaches for.

### GAP-017 — The SDK CI installs are unpinned
**What:** `.github/workflows/ci.yml`'s SDKs job runs `pip install -e ".[dev]"`
for `sdks/python`, and `npm ci` for `sdks/node`. The Node side is locked
(`package-lock.json` is committed); the Python side is exactly the floating
resolution GAP-016 closed for the backend, one directory over.
**Why it matters:** it is the suite guarding whether unprotected LLM traffic
ships. A silent dependency change under it is the same "green locally, red in
CI — or worse, green in both while testing different code" failure, on the most
security-load-bearing tests in the repo.
**Unblocks:** nothing. Smaller than the backend (the SDK has no runtime deps at
all — stdlib only by design — so the lock would cover test tooling), which is
why it is a follow-up rather than part of GAP-016. Same `scripts/lock.sh`
pattern.

### GAP-015 — No frontend test infrastructure
**What:** zero tests, no runner, no `test` script. `next build` is the only
frontend CI gate. Also 7 copy-pasted `SeverityBadge` definitions and no shared
component library (Phase 0 added the first shared component, `PreviewBadge`).
**Why it matters:** Phase 1 brings the MCP and anomalies pages to backend
parity with no regression net under them.
**Unblocks:** nothing external. Phase 1 stands up a runner.

### GAP-021 — The Trivy image gate has no exception ledger
**What:** the npm audit gate has `frontend/audit-exceptions.json` — a time-boxed,
owned, justified deferral mechanism with an expiry test (`test_audit_exceptions.py`
reddens the day an entry lapses). The **Trivy image scan** (`build-scan-sign`,
HIGH/CRITICAL, both the frontend and backend images) has **no equivalent**. It
is a bare `exit 1` on any finding.
**Why it matters:** today that is fine *because every image CVE has been
fixable* — the 2026-07-23 `next` batch (GAP-016 worked example) had a fixed
version, so the fix was to bump, not to defer. But container-layer findings
recur constantly (the Alpine base, bundled node-pkgs) and some land **unfixed**
(no patched version published yet) or **not reachable in our usage** (a CVE in a
code path the image never executes). The first time that happens, the image gate
hard-blocks **every** PR in the repo with no honest escape valve — and the
pressure in that moment is to do the one thing the npm policy forbids: turn the
gate warn-only. The mechanism to avoid that should exist *before* it is needed,
not be improvised under a red main.
**Design (mirror the npm ledger exactly, so there is one shape to learn):** a
JSON ledger (`image-scan-exceptions.json`) keyed by CVE id + image + package,
each entry carrying an exposure-grounded justification, an owner, and an expiry
(30d default, 90d max); a generator that emits the `.trivyignore` the action
consumes from it; and a `test_image_scan_exceptions`-style expiry test that
fails `pytest` on a lapsed entry. **Same hard bar:** a CVE with a fixed version
available gets **no** exception — fixed-version-available means fix, exactly as
the npm gate treats a production advisory.
**Unblocks:** nothing external. **Trigger to implement:** the first **unfixable**
(or verified-unreachable) HIGH/CRITICAL image CVE. Filed now to capture the
design while the npm parallel is fresh; deferred because this batch was fixable
and interleaving process work into the in-flight MCP increment chain buys
nothing a real red gate is not currently demanding.

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
