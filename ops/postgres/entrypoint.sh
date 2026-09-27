#!/usr/bin/env bash
set -euo pipefail
# Repository credentials are mounted separately from both database and backup data.
# Never echo this file or pass its contents in process arguments.
install -d -m 700 -o postgres -g postgres /etc/pgbackrest /backrest
install -m 600 -o postgres -g postgres /run/secrets/pgbackrest.conf /etc/pgbackrest/pgbackrest.conf
case "${UKDA_POSTGRES_TLS-false}" in
  true)
    # Keep private keys outside PGDATA so physical backups never contain them.
    install -d -m 700 -o postgres -g postgres /var/lib/postgresql/tls
    install -m 600 -o postgres -g postgres /run/secrets/server.crt /var/lib/postgresql/tls/server.crt
    install -m 600 -o postgres -g postgres /run/secrets/server.key /var/lib/postgresql/tls/server.key
    first_argument=${1:-}
    if [ "$first_argument" = postgres ] || [ "${first_argument:0:1}" = - ]; then
      set -- "$@" -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt \
        -c ssl_key_file=/var/lib/postgresql/tls/server.key -c ssl_min_protocol_version=TLSv1.2
    fi
    ;;
  false) ;;
  *) printf '%s\n' 'Invalid UKDA_POSTGRES_TLS setting' >&2; exit 1 ;;
esac
exec /usr/local/bin/docker-entrypoint.sh "$@"
