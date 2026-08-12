#!/bin/bash
set -euo pipefail

# Extra roles for CIS/HBA checks — count varies per profile.
user_count="${COLLECTOR_EXTRA_USERS:-6}"
pgbench_scale="${COLLECTOR_PGBENCH_SCALE:-10}"

for i in $(seq 0 $((user_count - 1))); do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'user${i}') THEN
        CREATE ROLE user${i} WITH LOGIN PASSWORD 'password' SUPERUSER;
      END IF;
    END
    \$\$;
EOSQL
done

pgbench -i -s "${pgbench_scale}" -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 || true

touch "${PGDATA}/.e2e-init-complete"
echo "bootstrap users (count=${user_count}) and pgbench scale=${pgbench_scale} ready"
