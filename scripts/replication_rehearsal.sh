#!/usr/bin/env bash
# Data-tier HA rehearsal: does replication actually stream, and does the
# failover actually elect?
#
# The Helm chart asserts a shape. scripts/verify_topology.py checks the
# rendered manifests match it. Neither runs anything, so neither can tell you
# that a row written to the primary arrives at the standby, or that Sentinel
# promotes a replica when the primary dies. That is what this does.
#
# Scope is deliberately narrow and stated up front: PostgreSQL and Redis only.
# ClickHouse and Redpanda are NOT rehearsed here (their images cannot be pulled
# in this environment) and this script never claims otherwise.
#
# Usage:  scripts/replication_rehearsal.sh [output-transcript-path]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
COMPOSE="deploy/staging-cell/docker-compose.rehearsal.yml"
TRANSCRIPT="${1:-docs/evidence/p13/replication-rehearsal.txt}"

mkdir -p "$(dirname "$TRANSCRIPT")"
exec > >(tee "$TRANSCRIPT") 2>&1

FAILURES=0
note_fail() { echo "   FAIL: $1"; FAILURES=$((FAILURES + 1)); }
note_ok() { echo "   ok:   $1"; }

dc() { docker compose -f "$COMPOSE" "$@"; }
pg() { dc exec -T "$1" psql -U platform -d platform -tAc "$2" 2>/dev/null | tr -d '[:space:]'; }
redis() { dc exec -T "$1" redis-cli "${@:2}" 2>/dev/null; }

echo "=============================================================="
echo " DATA-TIER REPLICATION & FAILOVER REHEARSAL"
echo "=============================================================="
echo "repository : $(git rev-parse HEAD)"
echo "branch     : $(git rev-parse --abbrev-ref HEAD)"
echo "started    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "scope      : PostgreSQL + Redis. ClickHouse and Redpanda are NOT"
echo "             exercised here — see docs/HA-TOPOLOGY.md."
echo
echo "images under test (digest-pinned):"
grep -E "^\s+image: " "$COMPOSE" | sed 's/^ */  /'
echo

# Start from nothing. This rehearsal PROMOTES a replica, so a second run
# against surviving state would begin with the roles already swapped and
# measure a different thing than the first run did. Evidence has to be
# reproducible from the recorded starting point.
echo "   ... recreating the cell from scratch"
dc down -v >/dev/null 2>&1
dc up -d --wait >/dev/null 2>&1 || { echo "   FAIL: the cell did not come up"; exit 1; }
echo "   all services healthy"
echo

echo "=============================================================="
echo " 1. PostgreSQL — streaming replication is live"
echo "=============================================================="
STATE=$(pg pg-primary "SELECT state FROM pg_stat_replication LIMIT 1")
SYNC=$(pg pg-primary "SELECT sync_state FROM pg_stat_replication LIMIT 1")
SLOT=$(pg pg-primary "SELECT active FROM pg_replication_slots LIMIT 1")
echo "   pg_stat_replication.state      = ${STATE:-<none>}"
echo "   pg_stat_replication.sync_state = ${SYNC:-<none>}"
echo "   replication slot active        = ${SLOT:-<none>}"
[ "$STATE" = "streaming" ] && note_ok "the standby is streaming" \
  || note_fail "no standby is streaming (state=${STATE:-<none>})"
[ "$SLOT" = "t" ] && note_ok "replication slot is held" \
  || note_fail "replication slot is not active — WAL could be recycled before the standby reads it"

echo
echo "=============================================================="
echo " 2. PostgreSQL — the standby is a REPLICA, not a second primary"
echo "=============================================================="
RECOVERY=$(pg pg-standby "SELECT pg_is_in_recovery()")
echo "   pg_is_in_recovery() on standby = ${RECOVERY:-<none>}"
[ "$RECOVERY" = "t" ] && note_ok "standby is in recovery (following the primary)" \
  || note_fail "standby is NOT in recovery — this is a split brain, both nodes accept writes"

READONLY=$(dc exec -T pg-standby psql -U platform -d platform -tAc \
  "CREATE TABLE should_not_exist (id int)" 2>&1 | grep -c "read-only")
[ "$READONLY" -ge 1 ] && note_ok "standby refuses writes" \
  || note_fail "standby ACCEPTED a write — divergence from the primary is now possible"

echo
echo "=============================================================="
echo " 3. PostgreSQL — a committed row actually arrives"
echo "=============================================================="
MARK="rehearsal-$(date -u +%s)"
pg pg-primary "CREATE TABLE IF NOT EXISTS ha_rehearsal (mark text primary key)" >/dev/null
pg pg-primary "INSERT INTO ha_rehearsal (mark) VALUES ('$MARK')" >/dev/null
echo "   wrote mark '$MARK' to the primary"

ARRIVED=""
for _ in $(seq 1 30); do
  ARRIVED=$(pg pg-standby "SELECT mark FROM ha_rehearsal WHERE mark = '$MARK'")
  [ "$ARRIVED" = "$MARK" ] && break
  sleep 1
done
[ "$ARRIVED" = "$MARK" ] && note_ok "the row is readable on the standby" \
  || note_fail "the row never arrived on the standby"

LAG=$(pg pg-primary "SELECT COALESCE(EXTRACT(EPOCH FROM write_lag), 0)::int FROM pg_stat_replication LIMIT 1")
echo "   write_lag (seconds)            = ${LAG:-0}"

echo
echo "=============================================================="
echo " 4. PostgreSQL — WAL is archived (the PITR precondition)"
echo "=============================================================="
# Force a segment switch so there is something to archive right now rather
# than waiting on archive_timeout.
pg pg-primary "SELECT pg_switch_wal()" >/dev/null
sleep 5
ARCHIVED=$(pg pg-primary "SELECT archived_count FROM pg_stat_archiver")
FAILED_ARCH=$(pg pg-primary "SELECT failed_count FROM pg_stat_archiver")
FILES=$(dc exec -T pg-primary sh -c "ls -1 /wal-archive 2>/dev/null | wc -l" | tr -d '[:space:]')
echo "   pg_stat_archiver.archived_count = ${ARCHIVED:-0}"
echo "   pg_stat_archiver.failed_count   = ${FAILED_ARCH:-0}"
echo "   files in the archive            = ${FILES:-0}"
[ "${ARCHIVED:-0}" -gt 0 ] && note_ok "WAL segments are reaching the archive" \
  || note_fail "nothing has been archived — 'replay WAL' has nothing to replay"
[ "${FAILED_ARCH:-1}" -eq 0 ] && note_ok "no archive failures" \
  || note_fail "archive_command is failing (${FAILED_ARCH} failures)"

echo
echo "=============================================================="
echo " 5. Redis — persistence and replication"
echo "=============================================================="
AOF=$(redis redis-primary config get appendonly | tail -1 | tr -d '[:space:]')
LINK=$(redis redis-replica info replication | grep master_link_status | cut -d: -f2 | tr -d '[:space:]')
echo "   primary appendonly              = ${AOF:-<none>}"
echo "   replica master_link_status      = ${LINK:-<none>}"
[ "$AOF" = "yes" ] && note_ok "AOF persistence is on" || note_fail "AOF is off — the window between snapshots is lost on restart"
[ "$LINK" = "up" ] && note_ok "replica link is up" || note_fail "replica is not connected"

redis redis-primary set ha:rehearsal "$MARK" >/dev/null
sleep 2
REPLICATED=$(redis redis-replica get ha:rehearsal | tr -d '[:space:]')
[ "$REPLICATED" = "$MARK" ] && note_ok "the key replicated to the replica" \
  || note_fail "the key did not replicate (got '${REPLICATED:-<none>}')"

echo
echo "=============================================================="
echo " 6. Redis — Sentinel quorum, then a REAL failover"
echo "=============================================================="
QUORUM=$(redis sentinel-1 -p 26379 sentinel ckquorum mymaster 2>&1 | tr -d '\r')
SENTINELS=$(redis sentinel-1 -p 26379 info sentinel | grep -o 'sentinels=[0-9]*' | cut -d= -f2 | tr -d '[:space:]')
echo "   ckquorum                        = ${QUORUM:-<none>}"
echo "   sentinels known to sentinel-1   = ${SENTINELS:-<none>}"
case "$QUORUM" in *OK*) note_ok "quorum can be reached" ;; *) note_fail "quorum cannot be reached — no failover could ever fire" ;; esac
[ "${SENTINELS:-0}" -ge 3 ] && note_ok "all 3 sentinels see each other" \
  || note_fail "only ${SENTINELS:-0} sentinels are visible"

BEFORE=$(redis sentinel-1 -p 26379 sentinel get-master-addr-by-name mymaster | head -1 | tr -d '[:space:]')
echo "   master before failover          = ${BEFORE:-<none>}"
echo "   ... stopping the primary to force an election"
dc stop redis-primary >/dev/null 2>&1

PROMOTED=""
for _ in $(seq 1 60); do
  PROMOTED=$(redis sentinel-1 -p 26379 sentinel get-master-addr-by-name mymaster | head -1 | tr -d '[:space:]')
  [ -n "$PROMOTED" ] && [ "$PROMOTED" != "$BEFORE" ] && break
  sleep 1
done
echo "   master after failover           = ${PROMOTED:-<none>}"
if [ -n "$PROMOTED" ] && [ "$PROMOTED" != "$BEFORE" ]; then
  note_ok "Sentinel promoted a replica — the failover is real, not configured-only"
else
  note_fail "no promotion occurred within 60s"
fi

ROLE=$(redis redis-replica info replication | grep '^role:' | cut -d: -f2 | tr -d '[:space:]')
echo "   surviving node role             = ${ROLE:-<none>}"
[ "$ROLE" = "master" ] && note_ok "the promoted node is now a master and accepts writes" \
  || note_fail "the surviving node is still '${ROLE:-<none>}'"

echo "   ... restoring the stopped primary"
dc start redis-primary >/dev/null 2>&1
# POLL, do not sleep-and-check once. The restored node boots as its own master
# (its config has no replicaof) and stays that way until Sentinel's next INFO
# refresh demotes it — order 10s, not instant. A fixed 8s wait read that normal
# window as a split brain and failed a healthy cluster; the window is the thing
# being measured, so measure it.
REJOINED=""
for i in $(seq 1 60); do
  REJOINED=$(redis redis-primary info replication | grep '^role:' | cut -d: -f2 | tr -d '[:space:]')
  [ "$REJOINED" = "slave" ] && break
  sleep 1
done
echo "   restarted node rejoined as      = ${REJOINED:-<none>} (after ${i}s)"
# The old primary must come back as a REPLICA. If it stays a master the cluster
# has two, and whichever one a client reaches decides what is true.
[ "$REJOINED" = "slave" ] && note_ok "the old primary was demoted to a replica (no split brain)" \
  || note_fail "the old primary was still '${REJOINED:-<none>}' after 60s — split brain"

echo
echo "=============================================================="
if [ "$FAILURES" -eq 0 ]; then
  echo " RESULT: PASS — every rehearsed claim held"
else
  echo " RESULT: FAIL — $FAILURES check(s) failed"
fi
echo " finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================="
[ "$FAILURES" -eq 0 ]
