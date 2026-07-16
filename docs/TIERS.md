# Tiering map

**Status:** Phase 0 (audit + flag mechanism). No capability has been removed.

This platform keeps every capability it has, but it does not polish them
equally. Spreading a single maintainer's effort evenly across ~25 API surfaces
produces a product where nothing is trustworthy. Tiering concentrates it:

| Tier | Meaning | Bar |
|---|---|---|
| **A** | The spearhead. Secure agent and MCP tool access, enforced inline. | Reference quality: HTTP + tenant-isolation tests, published benchmarks, documented failure modes. A design partner will probe these first, and every claim must survive it. |
| **B** | Shipped, labelled **preview**. | Works, usable, thinner tests. Tagged `preview` in OpenAPI and badged in the UI. No stability guarantee; not a load-bearing surface for a production integration. |
| **C** | Frozen. Dark until customer pull. | Code stays on disk and stays tested. Capability is **absent** by default behind `PLATFORM_ENABLE_*` — not a documented 403. |
| **Substrate** | The floor A and B stand on (auth, assets, connectors, dashboards). | Not a marketing surface. Not gated. Held to whatever its dependents need. |

The tier of a surface is a claim, so — per the repo's no-unbacked-claim rule —
it points at something mechanically checked. The source of truth is
[`backend/app/core/tiers.py`](../backend/app/core/tiers.py), and `create_app`
mounts **through** it. A router cannot drift from its documented tier: mounting
an unregistered prefix raises, and
[`test_tiers.py`](../backend/tests/unit/test_tiers.py) asserts that what mounts,
what is tagged, and what this table says are the same thing.

---

## Tier A — the spearhead

| Surface | Where | Reachable | Assessment |
|---|---|---|---|
| **MCP tool governance** — `/v1/mcp` (tools, inspect, violations, chain) | [`api/v1/mcp.py`](../backend/app/api/v1/mcp.py) | ✅ mounted | Backend surface is complete (8 endpoints). `test_mcp_gateway.py` covers the service beneath it. **No HTTP tests, no tenant-isolation test.** Frontend renders tools + violation counts only — no violation detail, no call-chain view, and `/inspect`, `/chain/{session_id}` and `/violations/{id}/resolve` are unused by the UI. Phase 1 closes all of it. |
| **Runtime agent** — inline proxy, 3-stage pipeline | [`runtime-agent/`](../runtime-agent) | ✅ ships | 84 Go tests. Coverage: proxy 75.7%, policy 75.8%, controlplane 82.8%; **`management` 0%, `cmd/agent` 0%** (GAP-010). No benchmark harness (GAP-002). Deny-by-default now holds end to end: Stage 2 honours `fail_behavior` (GAP-004 closed) and cold start is governed by `AGENT_NO_POLICY_BEHAVIOR`, defaulting closed in production (GAP-003 closed). |
| **Attack graph + behavioural anomalies** — `/v1/anomalies` | [`anomaly/`](../backend/app/anomaly) | ✅ mounted | Good unit coverage (`test_attack_graph.py` 14, `test_causal.py` 14). No HTTP tests. **No efficacy suite and no published false-positive budget** — detection quality is currently unmeasured (GAP-006). UI dumps raw JSON per anomaly. |
| **Blast radius** | [`aibom/risk.py:157`](../backend/app/aibom/risk.py) | ❌ **unreachable** | Exists only as a scoring factor inside the AIBOM risk model. Its router (`api/v1/aibom.py`, 3 endpoints) is not mounted, so there is no blast-radius surface over HTTP. Phase 1 mounts it and gives it a real endpoint (GAP-001). |
| **AI Guard** — `/v1/aiguard` (Stage-2 classify, Stage-3 judge) | [`api/v1/aiguard.py`](../backend/app/api/v1/aiguard.py) | ✅ mounted | Tier A by dependency: these back the agent's pipeline. 14 unit tests at service level; no HTTP tests. |
| **Policies / runtime ingest** — `/v1/policies`, `/v1/runtime` | — | ✅ mounted | Tier A by dependency: `/policies` serves the agent's policy cache, `/runtime` receives its telemetry. `test_policy_stages.py` 20; `/runtime` untested. |
| **SDK fail-closed** — Python + Node | [`sdks/`](../sdks) | ✅ ships | 38 Python + 36 Node tests against one shared contract, gated by the `SDKs (fail-closed)` CI job. Both suites mutation-verified: removing the fail-closed default kills 8 and 7 tests respectively. Was the most severe row in this document (GAP-005 closed). |

## Tier B — shipped, preview

Tagged `preview` in OpenAPI; badged in the UI via
[`PreviewBadge.tsx`](../frontend/src/components/PreviewBadge.tsx), whose route
list is asserted against the backend registry by a parity test.

| Surface | Reachable | Assessment |
|---|---|---|
| Evaluations — `/v1/evaluations` | ✅ mounted | No tests at any layer. |
| Findings — `/v1/findings` | ✅ mounted | No tests at any layer. |
| Test cases — `/v1/test-cases` | ✅ mounted | No tests at any layer. |
| Red team — `/v1/redteam` | ✅ mounted | Service tests only (`test_redteam_*`). |
| Reports — `/v1/reports` | ✅ mounted | No tests. Its framework list conflicts with `/v1/compliance`'s (GAP-008). |
| Compliance evidence — `/v1/compliance` | ✅ mounted | `test_compliance_matrix.py` + its meta-test — the strongest gate in the repo. |
| CI/CD gate — `actions/ai-security-gate` | ✅ ships | **Zero tests, no shellcheck, no CI job** (GAP-007). |
| SIEM: **Splunk + Elastic** | ❌ **unmounted** | Exporters well-tested (23 tests). The router was never mounted, so no SIEM config is reachable over the API. Phase 1 mounts it (GAP-001). Allowed by default via `TIER_B_EXPORTER_TYPES`. |

## Tier C — frozen, dark by default

Not deleted. The code stays, the tests stay, the capability is off.

| Surface | Flag | Why dark |
|---|---|---|
| Cross-tenant threat-intel clustering — `/v1/threat-intel` | `PLATFORM_ENABLE_THREAT_INTEL` | Clustering across tenants requires tenants. With one design partner it is a claim with nothing behind it. Router gated; nav link removed; page and API left on disk. |
| SIEM: Sentinel, Datadog, Chronicle, webhook | `PLATFORM_ENABLE_SIEM_EXTENDED` | Four more forwarders is surface area, not evidence. Gated at [`_build_one`](../backend/app/siem/exporters.py) — the config→exporter chokepoint — so a config written *before* the flag landed cannot keep forwarding. |
| SOAR incident sinks (PagerDuty, Opsgenie, webhook) | *(none needed)* | Has no router and never did — already dark by construction. 8 tests keep it honest. A flag here would be a claim that something was turned off, when nothing was ever on. |
| SCIM 2.0 — 13 endpoints | *(unmounted)* | On every procurement questionnaire; irrelevant to a 90-day POC, where OIDC login (substrate) suffices. **Promotion trigger: before first enterprise contract** (GAP-009). |
| IdP admin — 5 endpoints | *(unmounted)* | Same as SCIM. |

## Substrate

`/v1/auth`, `/v1/connectors`, `/v1/assets`, `/v1/discovery`, `/v1/dashboard`,
`/v1/dashboards`, `/v1/narratives`, `/v1/suppressions`, `/v1/validation`,
`/v1/remediation`, `/v1/risk-index`, `/v1/benchmark`, plus health probes.

Assessment: `/connectors`, `/assets`, `/discovery` and `/dashboard` are the
**only four of 25 mounted routers with HTTP-layer tests** — and the only four
with a cross-org isolation test. That ratio is now enforced rather than
rediscovered: see
[`test_router_coverage_ratchet.py`](../backend/tests/unit/test_router_coverage_ratchet.py),
whose exemption list may only shrink.

---

## What Phase 0 changed

Nothing about what the platform *can* do. Specifically:

- Added the tier registry and mounted every router through it.
- Tier C is now deny-by-default: `/v1/threat-intel` is absent from a default
  build's OpenAPI schema, and the four Tier C SIEM exporter types build no
  exporter on either the write or the forward path.
- Tier B carries `preview` in OpenAPI and a badge in the UI, with a parity test
  between the two lists.
- Added the router coverage ratchet (a one-way door on HTTP + tenant-isolation
  tests).
- Corrected two unbacked claims (README test count, agent latency target) per
  guardrail 1.

Deferred to Phase 1 by design: **mounting** `siem` and `aibom`. Phase 0 is a
no-behaviour-change phase, and mounting is a behaviour change — those routers
land with their HTTP and tenant-isolation tests, not before.
