# Detection-Content Authoring Guide (Pattern DSL)

How to write, test, and ship **complex event patterns** — the multi-condition,
causal/temporal/absence detections the platform runs over a flow of agent
events. Patterns are *content*: versioned, ATLAS-mapped, hot-reloadable,
shippable separately from the engine.

Engine: `app/patterns/` (compiler + evaluator + registry). Built-in library:
`app/patterns/library/builtin_patterns.json`.

## Anatomy of a pattern

```json
{
  "name": "cross-workspace-read-then-egress",
  "version": 1,
  "severity": "critical",
  "category": "data_exfiltration",
  "description": "Cross-workspace memory read, no active task, then unapproved egress within 60s.",
  "atlas_techniques": ["AML.T0057", "AML.T0024"],
  "all_of": [
    { "event": "memory_access", "where": { "workspace": { "ne": { "$ctx": "home_workspace" } } } },
    { "absent": { "event": "task_assignment" } },
    { "event": "external_api_call", "within": 60, "causally_after": "memory_access",
      "where": { "endpoint": { "not_in": { "$ctx": "tool_manifest" } } } }
  ]
}
```

### Conditions (`all_of`)

| Field | Meaning |
| --- | --- |
| `event` | The `event_type` to match (`request`, `tool_call`, `memory_access`, `external_api_call`, `policy_violation`, …). |
| `where` | Field predicates on the event (see operators). |
| `within` | Seconds: this event must occur within N seconds of its reference. |
| `causally_after` | The `event_type` of an earlier condition this event must be **causally downstream** of (poset depth ordering) — not merely later in time. |
| `absent` | Wraps `{event, where}`: the pattern matches only if **no** event matches it (negative detection — e.g. "no active task"). |

### Predicate operators (`where`)

`eq`, `ne`, `in`, `not_in`, `gte`, `lte`, `contains`, `exists`. Operand is a
literal **or** a context reference `{ "$ctx": "key" }` resolved against the
agent manifest passed to the evaluator (e.g. `home_workspace`, `tool_manifest`).

```json
{ "tool_name": { "not_in": { "$ctx": "tool_manifest" } } }
{ "rag_documents_retrieved": { "gte": 50 } }
{ "endpoint": { "contains": "internal." } }
```

## Author → test → ship

1. **Write** the spec (JSON). Map it to ≥1 MITRE ATLAS technique
   (`atlas_techniques`) — the AI-native control mapping.
2. **Validate** it compiles: `compile_pattern(spec)` raises
   `PatternValidationError` on bad structure (unknown op, `causally_after`
   referencing a non-earlier condition, empty `all_of`, …).
3. **Test it fires** against a synthetic flow with `evaluate(pattern, events,
   context=...)` — assert a `PatternMatch`, and write negatives (benign flows
   must NOT match). Mirror `tests/unit/test_patterns.py`.
4. **Map to ATLAS + version**; record the model/pattern in the AI-BOM so it's a
   tracked, risk-scored supply-chain component.
5. **Ship + hot-reload**: `publish_pattern_reload([...])` pushes specs over the
   `pattern:reload` Redis channel; every consumer's `PatternRegistry.apply_specs`
   atomically swaps the compiled set. Bad specs are skipped and logged, never
   fatal.

## Authoring rules of thumb

- **Prefer `causally_after` over `within` alone.** Temporal proximity is
  coincidental; causal ordering is the signal that kills false positives.
- **Use `absent` to encode "legitimate context".** The brief's example
  suppresses on an active `task_assignment` — that's how a real cross-agent
  read avoids alerting.
- **Bound `within`.** Unbounded time windows accumulate state; keep windows to
  the smallest that captures the attack.
- **One ATLAS technique minimum**, and add a `references` URL so analysts can
  pivot from the narrative to the technique.
- **Distinct `event_type` per positive condition** — `causally_after`
  references conditions by their event type.

## Confirmed-detection flywheel

When an analyst confirms a narrative a pattern produced, it auto-promotes to a
regression test case (`patterns.promotion.pattern_match_to_testcase` /
`feedback.service.narrative_to_testcase`) so the detection is never silently
lost. False positives suggest a suppression rule (human-approved, expiring).
