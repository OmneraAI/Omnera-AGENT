# syntax=docker/dockerfile:1.7
# Stage 1: Builder for extensions and tools
FROM postgres:15-alpine as builder

# Install compilation dependencies
RUN apk add --no-cache \
    build-base \
    clang \
    llvm \
    openssl-dev \
    libxml2-dev \
    perl-dev \
    python3-dev \
    linux-headers

# Build pg_partman & pg_cron
RUN git clone --branch v4.7.3 https://github.com/pgpartman/pg_partman.git && \
    cd pg_partman && \
    make && make install

RUN git clone --branch v1.5.2 https://github.com/citusdata/pg_cron.git && \
    cd pg_cron && \
    make && make install

# Stage 2: Production image
FROM postgres:15-alpine

# Runtime dependencies
RUN apk add --no-cache \
    openssl \
    libxml2 \
    py3-pip \
    perl \
    tzdata \
    pcre2 \
    libldap \
    krb5 \
    && pip3 install --no-cache-dir pgbackrest

# Security context
RUN addgroup -g 1001 -S postgres && \
    adduser -u 1001 -S -D -G postgres -H -h /var/lib/postgresql postgres && \
    chown -R postgres:postgres /var/lib/postgresql && \
    chmod 750 /var/lib/postgresql

# Copy compiled extensions
COPY --from=builder /usr/local/lib/postgresql /usr/local/lib/postgresql
COPY --from=builder /usr/local/share/postgresql/extension /usr/local/share/postgresql/extension

# Configuration templates
COPY docker-entrypoint-initdb.d/ /docker-entrypoint-initdb.d/
COPY config/postgresql.conf /usr/share/postgresql/postgresql.conf.sample
COPY config/pg_hba.conf /usr/share/postgresql/pg_hba.conf.sample

# Backup & WAL archiving
RUN mkdir -p /etc/pgbackrest && \
    chmod 750 /etc/pgbackrest && \
    mkdir -p /var/lib/pgbackrest && \
    chown postgres:postgres /var/lib/pgbackrest

# Monitoring (postgres_exporter)
ARG PROM_EXPORTER_VERSION=0.13.2
RUN wget -qO /usr/local/bin/postgres_exporter https://github.com/prometheus-community/postgres_exporter/releases/download/v${PROM_EXPORTER_VERSION}/postgres_exporter-${PROM_EXPORTER_VERSION}.linux-amd64.tar.gz && \
    tar -xzf /usr/local/bin/postgres_exporter -C /usr/local/bin/ --strip-components=1 && \
    chmod +x /usr/local/bin/postgres_exporter

# Health checks
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pg_isready -U postgres -d samsara

# Final runtime configuration
USER postgres
EXPOSE 5432 9187
VOLUME ["/var/lib/postgresql", "/var/lib/pgbackrest"]

# Custom entrypoint with backup/restore hooks
COPY entrypoints/postgres-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["postgres-entrypoint.sh"]
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
