FROM postgres:18-bookworm
ARG PGBACKREST_VERSION=2.59.1-1.pgdg12+1
RUN apt-get update && apt-get install --no-install-recommends -y pgbackrest=${PGBACKREST_VERSION} \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/ukda-postgres
COPY standby.sh /usr/local/bin/ukda-standby
RUN chmod 755 /usr/local/bin/ukda-postgres /usr/local/bin/ukda-standby
ENTRYPOINT ["ukda-postgres"]
CMD ["postgres"]
