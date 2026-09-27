#!/usr/bin/env bash
set -euo pipefail
install -d -m 700 -o postgres -g postgres "$PGDATA"
install -m 600 -o postgres -g postgres /run/secrets/replication.pgpass /var/lib/postgresql/.pgpass
export PGPASSFILE=/var/lib/postgresql/.pgpass
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  # The parent volume is dedicated to this replica. A failed partial seed is kept
  # for diagnosis, never silently deleted or overlaid on the next invocation.
  gosu postgres pg_basebackup --dbname='host=control-db port=5432 user=ukda_replica application_name=ukda_control_replica' \
    --pgdata="$PGDATA" --wal-method=stream --write-recovery-conf --checkpoint=fast --no-password
fi
test -f "$PGDATA/standby.signal"
exec gosu postgres postgres -D "$PGDATA" -c archive_mode=off -c synchronous_standby_names= \
  -c primary_conninfo='host=control-db port=5432 user=ukda_replica application_name=ukda_control_replica passfile=/var/lib/postgresql/.pgpass' \
  -c hot_standby=on
