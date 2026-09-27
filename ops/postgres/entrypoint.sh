#!/usr/bin/env bash
set -euo pipefail
# Repository credentials are mounted separately from both database and backup data.
# Never echo this file or pass its contents in process arguments.
install -d -m 700 -o postgres -g postgres /etc/pgbackrest /backrest
install -m 600 -o postgres -g postgres /run/secrets/pgbackrest.conf /etc/pgbackrest/pgbackrest.conf
exec /usr/local/bin/docker-entrypoint.sh "$@"
