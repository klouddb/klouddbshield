#!/bin/bash
set -euo pipefail

mkdir -p /etc/klouddbshield/db

# Preserve token from mounted server-node.yaml; generate file on first run if missing.
if [ ! -f /etc/klouddbshield/server-node.yaml ]; then
  cp /app/server-node.yaml /etc/klouddbshield/server-node.yaml
fi

ARGS=(-addr :8081 -dbdir /etc/klouddbshield/db)

# Optional CLI overrides; when unset, main-server reads db_driver/postgres_url from server-node.yaml.
if [ -n "${KSHIELD_DB_DRIVER:-}" ]; then
  ARGS+=(-db-driver "${KSHIELD_DB_DRIVER}")
fi

PG_URL="${DATABASE_URL:-${MAIN_SERVER_DATABASE_URL:-}}"
if [ -n "${PG_URL}" ]; then
  ARGS+=(-postgres-url "${PG_URL}")
fi

# Seed fleet-wide GUC drift golden baseline once main-server is listening.
(
  /app/seed-guc-baseline.sh || echo "GUC baseline seed failed (dashboard GUC drift page may be empty until upload)" >&2
) &

exec /app/main-server "${ARGS[@]}"
