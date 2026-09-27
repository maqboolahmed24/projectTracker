#!/usr/bin/env bash
set -euo pipefail
primary_host=${UKDA_REPLICATION_PRIMARY_HOST-control-db}
require_tls=${UKDA_REPLICATION_REQUIRE_TLS-false}
replica_mode=${UKDA_RECOVERY_REPLICA_MODE-local}
case "$replica_mode" in local|external) ;; *) printf '%s\n' 'Invalid recovery replica mode' >&2; exit 1 ;; esac
if [ "$replica_mode" = external ] && [ -z "${UKDA_REPLICATION_PRIMARY_HOST:-}" ]; then
  printf '%s\n' 'External replication requires an explicit primary host' >&2; exit 1
fi
if [ "${#primary_host}" -gt 253 ] || [[ ! "$primary_host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
  printf '%s\n' 'Invalid replication primary host' >&2; exit 1
fi
if [[ "$primary_host" =~ ^[0-9.]+$ ]]; then
  IFS=. read -r -a octets <<< "$primary_host"
  [ "${#octets[@]}" -eq 4 ] || { printf '%s\n' 'Invalid replication primary host' >&2; exit 1; }
  for octet in "${octets[@]}"; do
    if [[ ! "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || [ "$octet" -gt 255 ]; then
      printf '%s\n' 'Invalid replication primary host' >&2; exit 1
    fi
  done
fi
case "$require_tls" in true|false) ;; *) printf '%s\n' 'Invalid replication TLS setting' >&2; exit 1 ;; esac
if { [ "$primary_host" != control-db ] || [ "$replica_mode" = external ]; } && [ "$require_tls" != true ]; then
  printf '%s\n' 'External replication requires verified TLS' >&2; exit 1
fi
connection="host=$primary_host port=5432 user=ukda_replica application_name=ukda_control_replica passfile=/var/lib/postgresql/.pgpass"
if [ "$require_tls" = true ]; then
  install -d -m 700 -o postgres -g postgres /var/lib/postgresql/tls
  install -m 600 -o postgres -g postgres /run/secrets/replication-ca.crt /var/lib/postgresql/tls/replication-ca.crt
  connection="$connection sslmode=verify-full sslrootcert=/var/lib/postgresql/tls/replication-ca.crt"
fi
install -d -m 700 -o postgres -g postgres "$PGDATA"
install -m 600 -o postgres -g postgres /run/secrets/replication.pgpass /var/lib/postgresql/.pgpass
export PGPASSFILE=/var/lib/postgresql/.pgpass
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  # The parent volume is dedicated to this replica. A failed partial seed is kept
  # for diagnosis, never silently deleted or overlaid on the next invocation.
  gosu postgres pg_basebackup --dbname="$connection" \
    --pgdata="$PGDATA" --wal-method=stream --write-recovery-conf --checkpoint=fast --no-password
fi
test -f "$PGDATA/standby.signal"
exec gosu postgres postgres -D "$PGDATA" -c archive_mode=off -c synchronous_standby_names= \
  -c primary_conninfo="$connection" \
  -c hot_standby=on
