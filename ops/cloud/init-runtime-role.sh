#!/usr/bin/env bash
# Fresh clusters only. Existing clusters require an explicit reviewed migration.
set -euo pipefail
: "${RUNTIME_DB_PASSWORD_FILE:?External runtime password file required}"
export RUNTIME_DB_PASSWORD
RUNTIME_DB_PASSWORD="$(cat "$RUNTIME_DB_PASSWORD_FILE")"
if [[ -z "$RUNTIME_DB_PASSWORD" || "$RUNTIME_DB_PASSWORD" == *local_only* ]]; then
  printf '%s\n' 'A production runtime password is required' >&2
  exit 1
fi

# ssl=on alone permits cleartext connections. Reject them before the default
# host rules; keep Unix sockets for the privileged on-host recovery operator.
{ printf '%s\n' 'hostnossl all all all reject' 'hostnossl replication all all reject';
  cat "$PGDATA/pg_hba.conf"; } > "$PGDATA/pg_hba.conf.cloud"
mv "$PGDATA/pg_hba.conf.cloud" "$PGDATA/pg_hba.conf"
chmod 600 "$PGDATA/pg_hba.conf"

# Read the password from the process environment, never a command argument.
psql -X --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --set=ON_ERROR_STOP=1 <<'SQL'
\getenv admin_user POSTGRES_USER
\getenv database_name POSTGRES_DB
\getenv runtime_user RUNTIME_DB_USER
\getenv runtime_password RUNTIME_DB_PASSWORD
CREATE ROLE :"runtime_user" WITH LOGIN PASSWORD :'runtime_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON DATABASE :"database_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"database_name" TO :"runtime_user";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"runtime_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"admin_user" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"runtime_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"admin_user" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"runtime_user";
SQL
unset RUNTIME_DB_PASSWORD
