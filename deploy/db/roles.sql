-- deploy/db/roles.sql — one-time per environment, run as a superuser.
--
-- Tenant isolation Wall 2 (Postgres RLS, migration 0006_enable_rls) only binds
-- a role that does NOT have BYPASSRLS. Postgres superusers and the table owner
-- bypass RLS unless FORCE is set; the migration sets FORCE, but a superuser
-- still bypasses. So the APPLICATION must connect as asp_app (NOBYPASSRLS, no
-- DDL); Alembic/migrations keep using the owner role.
--
-- After running this, point the app DATABASE_URL at asp_app and keep the
-- owner DSN only for the migrate step (MIGRATIONS_DATABASE_URL).
--
--   psql "$OWNER_DSN" -v app_password="$ASP_APP_PASSWORD" -f deploy/db/roles.sql

CREATE ROLE asp_app LOGIN PASSWORD :'app_password' NOBYPASSRLS;

GRANT CONNECT ON DATABASE asp TO asp_app;
GRANT USAGE ON SCHEMA public TO asp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO asp_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO asp_app;

-- Future tables/sequences (created by later migrations as the owner) are granted
-- to asp_app automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO asp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO asp_app;
