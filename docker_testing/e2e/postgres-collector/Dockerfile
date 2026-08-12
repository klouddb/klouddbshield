# syntax=docker/dockerfile:1

FROM golang:1.22-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/ciscollector ./cmd/ciscollector

FROM postgres:17

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gettext-base openssl && \
    rm -rf /var/lib/apt/lists/*

ENV POSTGRES_USER=shielduser
ENV POSTGRES_PASSWORD=shieldpass
ENV POSTGRES_DB=shielddb

WORKDIR /app
COPY --from=builder /out/ciscollector /app/ciscollector
COPY docker_testing/e2e/postgres-collector/entrypoint.sh /app/entrypoint.sh
COPY docker_testing/e2e/postgres-collector/collector-profiles.sh /app/collector-profiles.sh
COPY docker_testing/e2e/postgres-collector/kshieldconfig.toml.template /app/kshieldconfig.toml.template
COPY docker_testing/e2e/postgres-collector/hba/ /app/hba/
COPY docker_testing/migrations/*.up.sql /docker-entrypoint-initdb.d/
COPY docker_testing/e2e/postgres-collector/enable-postgres-ssl.sh /app/enable-postgres-ssl.sh
COPY docker_testing/e2e/postgres-collector/init/97-profile-data.sh /docker-entrypoint-initdb.d/97-profile-data.sh
COPY docker_testing/e2e/postgres-collector/init/98-enable-logging.sh /docker-entrypoint-initdb.d/98-enable-logging.sh
COPY docker_testing/e2e/postgres-collector/init/99-bootstrap-users.sh /docker-entrypoint-initdb.d/99-bootstrap-users.sh

RUN chmod +x /app/ciscollector /app/entrypoint.sh /app/collector-profiles.sh /app/enable-postgres-ssl.sh \
    /docker-entrypoint-initdb.d/97-profile-data.sh \
    /docker-entrypoint-initdb.d/98-enable-logging.sh \
    /docker-entrypoint-initdb.d/99-bootstrap-users.sh

EXPOSE 5432
ENTRYPOINT ["/app/entrypoint.sh"]
