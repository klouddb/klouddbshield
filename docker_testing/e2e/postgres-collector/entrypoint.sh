#!/bin/bash
set -euo pipefail

export MAIN_SERVER_URL="${MAIN_SERVER_URL:-http://main-server:8081}"
export COLLECTOR_TOKEN="${COLLECTOR_TOKEN:-e2e-test-collector-token-do-not-use-in-prod}"

# Per-replica identity + profile (15 variants).
# shellcheck source=/app/collector-profiles.sh
source /app/collector-profiles.sh
resolve_container_identity
apply_collector_profile

export LOG_PARSER_LOGFILE="${LOG_PARSER_LOGFILE:-/var/lib/postgresql/data/log/*.log}"
export LOG_PARSER_HBAFILE="${LOG_PARSER_HBAFILE:-/var/lib/postgresql/data/pg_hba.conf}"

# Map unique host label to local Postgres (target_id uses POSTGRES_HOST; DB listens on 127.0.0.1).
sed -i "/[[:space:]]${POSTGRES_HOST}$/d" /etc/hosts 2>/dev/null || true
echo "127.0.0.1 ${POSTGRES_HOST}" >> /etc/hosts
export PGPASSWORD="${POSTGRES_PASSWORD}"

mkdir -p /etc/klouddbshield
envsubst < /app/kshieldconfig.toml.template > /etc/klouddbshield/kshieldconfig.toml

echo "Rendered kshieldconfig.toml for host ${APP_HOSTNAME} (${COLLECTOR_PROFILE_ID}, replica ${COLLECTOR_REPLICA_INDEX})"
echo "  scan_commands=${SCAN_COMMANDS}"
echo "  log_prefix=${LOG_PARSER_PREFIX}"
echo "  focus_tables=${COLLECTOR_FOCUS_TABLES}"
echo "  postgres_ssl=${POSTGRES_SSLMODE}"

psql_local() {
  psql -h 127.0.0.1 -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" "$@" 2>/dev/null \
    || psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" "$@"
}

wait_for_postgres() {
  local pgdata="${PGDATA:-/var/lib/postgresql/data}"
  until pg_isready -h 127.0.0.1 -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; do
    echo "Waiting for PostgreSQL TCP (${POSTGRES_HOST})..."
    sleep 1
  done
  until [ -f "${pgdata}/.e2e-init-complete" ] \
    || psql_local -tAc "SELECT 1 FROM collector_profile_meta LIMIT 1" >/dev/null 2>&1; do
    echo "Waiting for PostgreSQL seed scripts (${POSTGRES_HOST})..."
    sleep 1
  done
}

wait_for_main_server() {
  local url="${MAIN_SERVER_URL%/}/api/overview"
  until curl -sf "${url}" >/dev/null 2>&1; do
    echo "Waiting for main-server at ${url}..."
    sleep 2
  done
}

apply_hba_profile() {
  local hba="${PGDATA:-/var/lib/postgresql/data}/pg_hba.conf"
  local snippet="${COLLECTOR_HBA_SNIPPET:-}"

  [ -n "${snippet}" ] && [ -f "${snippet}" ] || return 0

  echo "Applying HBA profile ${COLLECTOR_PROFILE_ID} from ${snippet}"
  {
    echo ""
    echo "# --- e2e profile ${COLLECTOR_PROFILE_ID} (replica ${COLLECTOR_REPLICA_INDEX}) ---"
    cat "${snippet}"
  } >> "${hba}"

  psql_local -c "SELECT pg_reload_conf();" >/dev/null
}

apply_postgres_ssl() {
  [ "${COLLECTOR_SSL_ENABLED:-false}" = "true" ] || return 0

  echo "Enabling PostgreSQL SSL for ${POSTGRES_HOST} (${COLLECTOR_PROFILE_ID})..."
  /app/enable-postgres-ssl.sh

  echo "Restarting PostgreSQL to load SSL settings..."
  gosu postgres pg_ctl -D "${PGDATA:-/var/lib/postgresql/data}" -m fast -w restart

  wait_for_postgres
}

seed_log_activity() {
  local i
  for i in 1 2 3; do
    psql_local -c "SELECT 1 AS profile_probe_${COLLECTOR_PROFILE_INDEX};" >/dev/null 2>&1 || true
  done
}

# Start PostgreSQL using the official entrypoint (runs initdb scripts on first boot).
/usr/local/bin/docker-entrypoint.sh postgres &
PG_PID=$!

wait_for_postgres
apply_postgres_ssl
apply_hba_profile
seed_log_activity
wait_for_main_server

echo "Running initial scans (CIS, HBA, PII, SSL, log parser all) and pushing to main-server..."
/app/ciscollector --config /etc/klouddbshield --json --output-type json \
  --run-postgres --hba-scanner --piiscanner --ssl-check \
  --logparser all \
  --prefix "${LOG_PARSER_PREFIX}" \
  --file-path "${LOG_PARSER_LOGFILE}" \
  --hba-file "${LOG_PARSER_HBAFILE}" || {
  echo "Initial scan failed; continuing with cron mode"
}

echo "Starting ciscollector cron (--setup-cron, same as systemd ciscollector.service)..."
trap 'kill -TERM "${PG_PID}" 2>/dev/null || true' EXIT INT TERM

exec /app/ciscollector --setup-cron --config /etc/klouddbshield --json
