# AI Security Platform — RAPIDE Enterprise Roadmap

> From flat-correlation MVP to causal, cross-agent, enterprise-ready GA.
> Integrates the Rapide (DARPA/Stanford CEP) architecture as the detection spine.
> Sprint cadence: 2 weeks. Total: 16 sprints (~8 months) across 8 phases + 4 continuous workstreams.

## Reading this roadmap

- **Phases** group sprints by architectural milestone. They are mostly sequential; the dependency notes call out what can parallelize.
- Every sprint has: **Objective · Tasks · Features shipped · Exit criteria · Depends on · Risk.**
- **Continuous workstreams** (security, testing, docs, platform-observability) run across every sprint — defined once at the end.
- File paths reference the current repo so each task lands somewhere concrete.

## Current-state ground truth (the starting line)

| Reality | Implication for the roadmap |
|---|---|
| `RuntimeEvent` has `session_id` only; no causal fields | Phase A must add the poset spine before anything else works |
| Redpanda declared (`config.py:43`) but **zero** producers/consumers | Phase B activates the streaming layer that is currently fiction |
| `pipeline.py` ships `_NoopStage2` / `_NoopStage3` | Phase 0 un-stubs ML + judge; "3-stage pipeline" is regex-only today |
| `detector.py` = 3 hardcoded stats, pull-based, per-asset batch | Phases B–D convert it to a streaming EPA fleet with a pattern DSL |
| Attack graph: "sessions never cross assets" | Phase C removes this; unlocks multi-agent threat detection |
| `Anomaly` emitted with no triage/disposition/suppression | Phase E builds the feedback loop — the actual alert-fatigue cure |
| Strong identity/SCIM/audit/SIEM/SOAR already shipped | Not re-built; only extended where narratives/metrics require |

---

# PHASE 0 — Truth-in-Architecture (Sprints 1–2)

Make the README true before building on it. Un-stub the pipeline, prove the streaming path, and instrument a baseline so later efficacy claims are measurable.

## Sprint 1 — Un-stub the policy pipeline (Stage 2 ML + Stage 3 judge)
**Objective:** Make "regex → ONNX → LLM judge" real in the control plane and the Go agent.
**Tasks:**
- Replace `_NoopStage2` in `backend/app/policy/pipeline.py` with a real ONNX classifier (`policy/stage2_onnx.py` is present but inert) — load `protectai/deberta-v3-base-prompt-injection-v2`, expose `classify()` returning calibrated confidence.
- Implement confidence routing: high→action, low→pass, uncertain-band→Stage 3.
- Replace `_NoopStage3` with an LLM-judge stage reusing the connector pool (`connectors/`).
- Mirror in Go agent: wire `runtime-agent/policy/` stage2/stage3 hooks (CGo ONNX bridge or sidecar inference call).
- Calibrate uncertain-band thresholds against the 50-case OWASP library (`testcases/library.py`).
**Features:** Functional three-stage enforcement; per-stage latency captured (fields already exist in `runtime_event.py`).
**Exit criteria:** Stage 2/3 fire in integration tests; OWASP library detection rate measured and recorded as baseline; p95 added latency budget documented.
**Depends on:** none. **Risk:** ONNX runtime packaging in Go (CGo) — spike first; fall back to inference sidecar if CGo is painful.

## Sprint 2 — Streaming spine + efficacy baseline
**Objective:** Make Redpanda real and capture the "before" metrics RAPIDE will improve.
**Tasks:**
- Add a Redpanda producer in the runtime agent telemetry path (`runtime-agent/telemetry/buffer.go`) → topic `runtime.events`. Keep ClickHouse as the durable replay/audit store (dual-write).
- Add a control-plane consumer scaffold (`backend/app/streaming/`) — consumer group, offset management, replay from ClickHouse.
- Build an **efficacy harness**: instrument current alert volume, FP rate (via manual labels on a captured corpus), MTTD on synthetic incidents. Store as the `baseline` snapshot.
- Stand up platform self-observability: OpenTelemetry traces + Prometheus metrics on the API and agent (you already ship a ServiceMonitor template in Helm).
**Features:** Live event bus; baseline efficacy dashboard; platform metrics.
**Exit criteria:** Events flow agent→Redpanda→consumer in staging; baseline numbers committed to `docs/efficacy/baseline.md`.
**Depends on:** none (parallel with S1). **Risk:** dual-write consistency — make ClickHouse the source of truth, Redpanda best-effort.

---

# PHASE A — Poset Causal Spine (Sprints 3–4)

The single highest-leverage change. Replace inferred temporal edges with explicit causal relationships.

## Sprint 3 — Causal event model + context propagation
**Objective:** Every event knows what caused it and which root request it descends from.
**Tasks:**
- Extend `backend/app/telemetry/runtime_event.py` and `clickhouse/init/01-create-runtime-events.sql` with: `parent_event_id`, `root_event_id`, `causal_depth`, `correlation_key`. Write the Alembic-equivalent ClickHouse migration + a `RUNTIME_EVENTS_COLUMNS` update (keep `to_row()` aligned — there's a guard comment for this).
- Mirror fields in `runtime-agent/telemetry/event.go`.
- Implement **context propagation** in the Go agent (`runtime-agent/proxy/handler.go`): adopt W3C `traceparent` semantics — when a response yields a downstream call, propagate `root_event_id` + `correlation_key`. Stamp `parent_event_id` on each emitted event.
- SDK propagation: `sdks/python` and `sdks/node` wrappers must forward/accept the trace context so multi-process agent fleets thread correctly.
**Features:** Causal lineage on every event; cross-process trace continuity.
**Exit criteria:** A 3-hop synthetic agent chain produces events with correct `parent/root/depth`; backfill path documented for pre-migration data (null lineage tolerated).
**Depends on:** S2 (streaming carries the context cleanly). **Risk:** context loss across async tool calls — test fan-out/fan-in explicitly.

## Sprint 4 — Poset graph engine (refactor attack graph)
**Objective:** Turn the per-session timeline into a true causal DAG.
**Tasks:**
- Refactor `backend/app/anomaly/attack_graph.py::_fold_rows` to build edges from `parent_event_id`, not `prev_node_by_session`.
- Partition graphs by `root_event_id`/`correlation_key` instead of `(org, asset)` — keep an asset view as a projection, not the primitive.
- Add concurrency representation (events with same parent = concurrent siblings) so the poset captures "A caused B, concurrent with C."
- Add a poset query API: given any event, return its full causal subtree (this becomes the analyst timeline in Phase E).
**Features:** Causal DAG substrate; causal-subtree query.
**Exit criteria:** Graph reconstructs known causal chains from S3 fixtures; existing anomaly tests pass against the new edge source.
**Depends on:** S3. **Risk:** graph size under adversarial fan-out — cap depth/breadth, fall back to `"*"` collapse (pattern already used in `_classify`).

---

# PHASE B — EPA Streaming Fleet (Sprints 5–6)

Convert the batch, pull-based detector into stateful, continuous Event Processing Agents.

## Sprint 5 — Per-agent EPA runtime
**Objective:** One stateful processor per `agent_instance_id`, maintaining a behavioral envelope.
**Tasks:**
- New package `backend/app/epa/`. Define `EPA` lifecycle: subscribe to `runtime.events`, maintain per-instance state in Redis 7 (already deployed) — typical tool sequences, comms graph, memory cadence, risk distribution.
- Port the math in `detector.py` (z-score volume, novel transition, risk inflation) into **continuous evaluators** that run against the live envelope rather than two recomputed windows.
- Implement **behavioral baselining** with cold-start safety (mirror detector's "no baseline → no anomaly" honesty).
- Implement **drift detection**: track rate + shape of envelope change; classify gradual (task switch) vs abrupt (compromise).
**Features:** Live per-agent monitoring; drift classification; no more on-demand recompute.
**Exit criteria:** EPA detects the same anomalies the batch detector did, in stream, with state surviving restart (Redis-backed); throughput target met under load test (extend `loadtest/locustfile.py`).
**Depends on:** Phase A. **Risk:** stateful consumer scaling — partition by `agent_instance_id` hash across consumer group.

## Sprint 6 — EPA supervision, negative events, resource-curve detection
**Objective:** Production-grade EPA fleet with absence detection.
**Tasks:**
- EPA supervisor: lifecycle, health, rebalancing on partition moves, backpressure handling.
- **Negative/absence detection** (entirely missing today): expected-but-absent events — dropped heartbeats (`runtime-agent/management/heartbeat.go` exists), skipped security checks. Time-wheel of expected events per envelope.
- **Trajectory/acceleration detection** for token & API-rate exhaustion (brief §4.4) — catch the acceleration curve, not a static threshold.
- Deprecate the pull-based `detect_for_asset`; keep `GET /v1/anomalies` as a read over EPA output for backward compat.
**Features:** Absence detection; resource-exhaustion early warning; self-healing EPA fleet.
**Exit criteria:** Heartbeat-drop and token-acceleration scenarios fire; EPA fleet survives broker partition rebalance with no missed events.
**Depends on:** S5. **Risk:** false absence alerts on legitimate idle agents — require envelope maturity before absence alerting.

---

# PHASE C — Cross-Agent Correlation & Tier Abstraction (Sprints 7–8)

Unlock the threat classes that are structurally impossible today.

## Sprint 7 — Cross-agent correlation EPA
**Objective:** Detect attacks that span multiple agents.
**Tasks:**
- New EPA type subscribing across all instances sharing a `correlation_key`/`root_event_id`.
- Implement the brief's headline scenarios: **multi-agent prompt-injection propagation** (§4.1) — tainted input → behavioral shift in A → message to B → correlated shift → anomalous tool call; and **coordinated low-and-slow exfiltration** (§4.2) — accumulation patterns over sliding windows across agents.
- EPA-to-EPA event bus (dedicated topic) so per-agent EPAs feed signals to the correlation EPA.
**Features:** Cross-agent kill-chain detection — the core differentiator.
**Exit criteria:** Red-team propagation chain (built in Phase F) surfaces as ONE correlated detection with full causal path, not N isolated alerts.
**Depends on:** Phases A+B. **Risk:** correlation-key sparsity if agents don't propagate context — gate on S3 propagation coverage metric.

## Sprint 8 — Three-tier abstraction maps
**Objective:** Formalize Tier-1→2→3 so only actionable narratives reach humans.
**Tasks:**
- **Tier 2 (behavioral primitives):** extend `_classify` into *sequence recognizers* — auth handshakes, retrieval patterns, tool-invocation chains. Emit T2 events, not raw.
- **Tier 3 (threat narratives):** correlation EPA emits a new `ThreatNarrative` domain entity (new `backend/app/narratives/`) replacing raw `Anomaly` as the SOAR/SIEM payload.
- Define the executable "maps" (T1→T2, T2→T3) as configuration, versioned.
- Wire `ThreatNarrative.correlation_id` = `root_event_id` so downstream `soar/incidents.py::Incident` carries the full causal timeline.
**Features:** Orders-of-magnitude alert reduction by construction; human-actionable narratives only.
**Exit criteria:** On a mixed traffic replay, T3 alert count is ≥1 order of magnitude below raw event-derived alerts; every T3 narrative carries a reconstructable timeline.
**Depends on:** S7. **Risk:** over-aggressive abstraction hiding real signal — keep T1/T2 queryable for drill-down; never delete, only suppress surfacing.

---

# PHASE D — Pattern DSL / Detection-as-Code (Sprints 9–10)

Make detection content, not code — the moat and the customer-tunability story.

## Sprint 9 — Complex Event Pattern DSL + compiler
**Objective:** Express multi-condition, causally-ordered, temporally-windowed patterns declaratively.
**Tasks:**
- Design the pattern spec (YAML/JSON) supporting `all_of`, `absent`, `within`, `causally_after`, field predicates against agent manifest/identity. (Mirror the brief §3.3 four-condition example.)
- Build `backend/app/epa/compiled_pattern.py` — compile specs to evaluators, mirroring the existing `policy/compiled.py` pattern.
- Runtime evaluator integrated into the EPA fleet; hot-reload via Redis pub/sub (you already do this for policies in `services/policy_pubsub.py`).
- Pattern CRUD API + RBAC + audit-log emission (reuse `auth/rbac.py`, `security/audit_log.py`).
**Features:** Detection-as-code; per-org custom patterns; hot reload.
**Exit criteria:** The README/brief example pattern ("cross-workspace read, no task context, unapproved egress within 60s") is expressible, compiles, and fires correctly with near-zero FP on benign traffic.
**Depends on:** Phase C. **Risk:** DSL expressiveness vs safety — sandbox evaluation, bound time windows and accumulation memory.

## Sprint 10 — Pattern library + MITRE ATLAS mapping
**Objective:** Ship a curated, mapped detection library — the defensible IP.
**Tasks:**
- Author the "top 10 AI agent threat" pattern library (propagation, exfil, drift/hijack, tool-abuse escalation, resource exhaustion, etc.).
- Map every pattern to **MITRE ATLAS** (AI-native analog to your existing OWASP LLM / NIST AI RMF report templates in `reports/`).
- Pattern versioning, signing, and a distribution channel (patterns ship like content, separate from code releases).
- Feed confirmed real-world detections into the **existing red-team auto-promotion** path (`redteam/`) to grow the regression suite.
**Features:** Shippable, mapped, versioned detection library; detection↔red-team flywheel.
**Exit criteria:** ≥10 ATLAS-mapped patterns in the library, each with a red-team scenario that triggers it; pattern updates deployable without a platform release.
**Depends on:** S9. **Risk:** library quality = product credibility — gate each pattern behind red-team validation before publish.

---

# PHASE E — Threat Narratives, Triage & Feedback Loop (Sprints 11–12)

The actual alert-fatigue cure. Without this, the platform *generates* fatigue.

## Sprint 11 — Analyst workbench + triage state
**Objective:** Give analysts a causal-timeline workbench and disposition workflow.
**Tasks:**
- `ThreatNarrative` triage states: open → confirmed/false_positive/suppressed → resolved; analyst assignment; disposition + rationale.
- Persist disposition through the hash-chained audit log (`security/audit_log.py`) for evidentiary integrity.
- Frontend: new analyst workbench (`frontend/src/app/`) rendering the causal timeline (poset subtree from Phase A), kill-chain visualization, one-click drill to T1/T2 evidence.
- Incident timeline reconstruction wired into SOAR payloads.
**Features:** Investigation time collapse (brief §6 target: 2–8h → 15–45m); auditable disposition.
**Exit criteria:** Analyst can triage a narrative end-to-end with full causal context; disposition is tamper-evident.
**Depends on:** Phase C/D. **Risk:** UI complexity — usability-test the timeline with a real SOC workflow before GA.

## Sprint 12 — Feedback loop + suppression learning
**Objective:** Close the loop so FPs train the system down over time.
**Tasks:**
- FP dispositions → auto-suggested **suppression rules** (pattern guards), human-approved before activation.
- Confirmed narratives → red-team regression promotion (reuse `redteam/` promotion).
- Adaptive thresholds: feed disposition signal back into EPA envelope tuning.
- FP-rate trend reporting per pattern (drives library quality decisions).
**Features:** Self-tuning detection; measurable FP decline; alert volume governance.
**Exit criteria:** Demonstrate FP-rate reduction across two tuning cycles on a fixed replay corpus; suppression changes are audited and reversible.
**Depends on:** S11. **Risk:** suppression hiding true positives — every suppression expires/recertifies; never permanent.

---

# PHASE F — Efficacy Instrumentation & Validation (Sprints 13–14)

Prove the numbers instead of claiming them. Adversarial validation.

## Sprint 13 — Red-team validation harness for multi-agent attacks
**Objective:** Generate the attack scenarios that validate every claim.
**Tasks:**
- Extend `redteam/` with **multi-agent campaign generation**: propagation chains, coordinated exfil, gradual hijack, tool-abuse escalation.
- Automated validation suite: each RAPIDE scenario from the brief (§4.1–4.4) as a repeatable test that asserts detection + correct causal narrative.
- Purple-team replay: inject campaigns into staging, measure detection rate, FP rate, MTTD against the Phase 0 baseline.
**Features:** Continuous detection-efficacy regression; provable coverage.
**Exit criteria:** All four brief scenarios detected with full kill-chain; efficacy metrics recorded vs baseline.
**Depends on:** Phases C–E. **Risk:** scenarios not representative — review against real incident reports / ATLAS case studies.

## Sprint 14 — Efficacy reporting + scale validation
**Objective:** Turn measured improvement into a customer-facing, defensible artifact.
**Tasks:**
- Efficacy report template in `reports/` (alongside exec/OWASP/NIST/SOC2/EU-AI-Act): alert-volume reduction, FP rate, MTTD, investigation time — **measured, per-deployment**, not marketing estimates.
- Scale test: drive realistic agent-fleet event volumes through the full poset→EPA→narrative path; validate p95 latency, EPA throughput, ClickHouse/Redpanda capacity.
- Capacity planning + sizing guide for `docs/OPERATOR-RUNBOOK.md`.
**Features:** Per-deployment efficacy proof; published scale envelope.
**Exit criteria:** Platform sustains target event rate within SLOs; efficacy report generated from real telemetry, not constants.
**Depends on:** S13. **Risk:** the brief's 85–95%/<5% targets may not hold — report *actuals*; treat the brief numbers as hypotheses, not guarantees.

---

# PHASE G — Enterprise Hardening (Sprint 15)

## Sprint 15 — HA, residency, DR, multi-region
**Objective:** Survive the procurement and ops review.
**Tasks:**
- HA for every tier: PG (replication/failover), Redis (sentinel/cluster), ClickHouse (replicated MergeTree), Redpanda (RF≥3), stateless API behind LB; EPA fleet rebalancing already from Phase B.
- **Data residency**: tenant→region pinning for telemetry + operational data; document data-flow per region.
- Tenant-level rate isolation / noisy-neighbor protection at the API and EPA layers.
- DR: backup/restore runbooks, RPO/RTO targets, ClickHouse + PG point-in-time recovery, Redpanda topic recovery; game-day test.
- Finalize Helm/K8s for multi-region (`deploy/helm`, `deploy/k8s`).
**Features:** Production HA/DR; residency controls; tenant isolation.
**Exit criteria:** Documented RPO/RTO met in a game-day; region-pinning verified; failover tested with no data loss on the audit log.
**Depends on:** core platform stable. **Risk:** ClickHouse replication ops complexity — budget spike time.

---

# PHASE H — GA Readiness (Sprint 16)

## Sprint 16 — Security audit, compliance, launch
**Objective:** Ship.
**Tasks:**
- Third-party **penetration test** + remediation (focus: agent proxy, SDK trust boundary, pattern DSL sandbox, multi-tenant isolation).
- **SOC 2 Type II** readiness pass — leverage existing evidence-pack builder (`compliance/evidence_pack.py`); close control gaps.
- Complete `docs/SECURITY-AUDIT-CHECKLIST.md`; finalize EU AI Act / NIST AI RMF report fidelity.
- Commercial readiness: metering/tiers (the roadmap's deferred "Tier 4"), billing hooks, license enforcement (BUSL-1.1).
- GA docs: install, operator runbook, detection-content authoring guide, API reference, upgrade/migration guide.
- Launch checklist: support runbooks, SLA definition, on-call, status page.
**Features:** Audited, compliant, commercially-packaged GA product.
**Exit criteria:** Pen-test criticals closed; SOC 2 evidence complete; GA docs published; metering live.
**Depends on:** all phases. **Risk:** pen-test findings reset timeline — start the engagement in S14, not S16.

---

# Continuous workstreams (every sprint)

| Workstream | What runs continuously |
|---|---|
| **Testing** | Maintain ≥80% coverage (your standing bar); every new module ships unit + integration tests; extend `loadtest/locustfile.py` each phase; TDD on detection logic. |
| **Security** | `security-reviewer` pass before every merge; no hardcoded secrets (you have `secret_gate.py`); threat-model each new boundary (Redpanda, EPA state, DSL sandbox, cross-agent bus). |
| **Docs** | Keep `README.md` capability table honest (un-stub claims as they ship); update `OPERATOR-RUNBOOK.md` per ops-affecting change; ADRs for binding decisions. |
| **Platform observability** | OTel traces + Prometheus metrics on every new service; EPA fleet health dashboards; track the platform's *own* SLOs. |

# Dependency map (critical path)

```
S1 ─┐
S2 ─┴→ S3 → S4 → S5 → S6 → S7 → S8 → S9 → S10 → S11 → S12 → S13 → S14 → S15 → S16
       (Phase A)   (Phase B)   (Phase C)   (Phase D)    (Phase E)    (Phase F)  (G)  (H)
```
- S1 and S2 parallelize.
- Phase G hardening tasks can begin partially during Phases D–F (HA infra has no detection dependency).
- Pen-test engagement (H) must be booked by S14.

# Reconciliation with the brief's 12-month plan

| Brief phase | This roadmap |
|---|---|
| Phase 1 (telemetry, poset, baselines) | Sprints 2–4 |
| Phase 2 (EPA fleet, T1→T2 maps, first pattern library) | Sprints 5–6, 8–10 |
| Phase 3 (T2→T3 narratives, SOC integration, red-team validation) | Sprints 8, 11, 13 |
| Phase 4 (production hardening, expanded patterns, automated response) | Sprints 12, 14–16 |

The brief's 12-month estimate is realistic *only* because most enterprise plumbing (identity, audit, SIEM/SOAR, compliance) is already shipped. The net-new work is the RAPIDE spine (Phases A–F), which is the 8 months of critical path above.
