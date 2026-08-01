#!/usr/bin/env bash
# Runs once, on the primary's first boot, from docker-entrypoint-initdb.d.
#
# Creates the dedicated replication role and lets it in from the cell network.
# A separate role rather than the superuser: primary_conninfo ends up in the
# standby's configuration and in its process arguments, so whatever credential
# replication uses is a credential that leaks easily. REPLICATION alone cannot
# read table data, create objects, or drop anything.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE ${REPL_USER} WITH REPLICATION LOGIN PASSWORD '${REPL_PASSWORD}';
SQL

# scram-sha-256, not trust or md5. The rehearsal is meant to exercise the same
# authentication path the cell uses; "it worked with trust" proves nothing
# about a configuration that does not use trust.
cat >> "$PGDATA/pg_hba.conf" <<HBA
host    replication     ${REPL_USER}     all     scram-sha-256
HBA

# The WAL archive directory is prepared by the archive-init service, which runs
# as root before this container starts. It cannot be done here: scripts in
# docker-entrypoint-initdb.d already run as postgres, and a named volume is
# created root-owned, so the chown fails with EPERM and takes the primary down
# on first boot. Fixing it by running the database as root would be a much
# worse answer than adding one init step.
