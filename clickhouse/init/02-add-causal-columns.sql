-- Migration: add the poset causal-lineage columns to an EXISTING
-- telemetry.runtime_events table (Sprint 3).
--
-- The base script 01-create-runtime-events.sql only runs against a fresh
-- database. Deployments that already initialized the table before Sprint 3
-- apply this ALTER. It is idempotent (IF NOT EXISTS) and safe to re-run.
--
-- Pre-Sprint-3 rows keep NULL lineage; the attack-graph builder treats a
-- NULL parent as a root, so historical data degrades gracefully rather
-- than breaking the poset construction.

ALTER TABLE telemetry.runtime_events
    ADD COLUMN IF NOT EXISTS parent_event_id Nullable(UUID);

ALTER TABLE telemetry.runtime_events
    ADD COLUMN IF NOT EXISTS root_event_id Nullable(UUID);

ALTER TABLE telemetry.runtime_events
    ADD COLUMN IF NOT EXISTS causal_depth UInt16 DEFAULT 0;

ALTER TABLE telemetry.runtime_events
    ADD COLUMN IF NOT EXISTS correlation_key String DEFAULT '';

-- Data-skipping index so Phase C's cross-agent correlation EPA can pull a
-- whole flow by correlation_key without scanning every partition.
ALTER TABLE telemetry.runtime_events
    ADD INDEX IF NOT EXISTS idx_correlation_key correlation_key
    TYPE bloom_filter GRANULARITY 4;
