# E2E Docker stack (ciscollector + main-server)

End-to-end test environment: PostgreSQL with dummy data, `ciscollector` pushing scan results to `main-server`, and the dashboard on your host at **http://localhost:8081/**.

## Layout

```
docker_testing/e2e/
├── docker-compose.yml    # main-server + single collector service (scaled)
├── .env
├── run.sh
├── run-postgres.sh       # main-server storage on PostgreSQL (profile postgres-storage)
├── main-server/
└── postgres-collector/
```

## Quick start

```sh
cd docker_testing/e2e
chmod +x run.sh
./run.sh
```

Open **http://localhost:8081/** in your browser.

### Main-server storage (SQLite vs PostgreSQL)

By default the dashboard API persists to **SQLite** at `/etc/klouddbshield/db/main-server.sqlite` inside the `main-server` container volume.

To use **PostgreSQL** as central main-server storage (matches production `-db-driver=postgres`):

```sh
# Option A — helper script (env vars)
chmod +x run-postgres.sh
COLLECTOR_COUNT=3 ./run-postgres.sh

# Option B — .env
KSHIELD_DB_DRIVER=postgres
MAIN_SERVER_DATABASE_URL=postgres://kshield:kshield@main-server-db:5432/kshield?sslmode=disable
./run.sh

# Option C — server-node.yaml (in /etc/klouddbshield/server-node.yaml or e2e seed file)
db_driver: postgres
postgres_url: postgres://kshield:kshield@main-server-db:5432/kshield?sslmode=disable
```

Precedence: environment variables override CLI flags; both override `server-node.yaml`.

This starts an extra service **`main-server-db`** (Postgres 17, profile `postgres-storage`). Collector containers still run their **own** Postgres for scan targets — only the central dashboard DB moves to PostgreSQL.

Reset postgres storage volume:

```sh
./run-postgres.sh down -v   # removes main-server-pg-data volume too
```

### How many Postgres servers?

Set `COLLECTOR_COUNT` in `.env` (default `2`). `run.sh` uses native Compose scaling:

```sh
docker compose up --scale collector=N
```

Each replica is a separate container with its own Postgres + dummy data. Identity comes from the container hostname (e.g. `e2e-collector-1`), so each appears as a distinct host on the dashboard.

**Per-replica profiles (15 variants):** replica `N` maps to profile `(N-1) mod 15`. Each profile differs in:

| Dimension | How it varies |
|-----------|----------------|
| **Config** | `scan_commands`, cron schedules (`COLLECTOR_SCHEDULE`, `PII_SCHEDULE`, `LOG_PARSER_SCHEDULE`) |
| **Data** | Profile-specific rows in focus tables + dedicated schema `profile-XX` |
| **Tables** | Focus table pairs (e.g. `users,contacts` vs `employees,orders`) + `profile-XX.inventory` / `audit_trail` |
| **Log prefix** | Unique `log_line_prefix` / `[collector.logparser].prefix` per profile |
| **HBA** | Appended rules from `postgres-collector/hba/profile-XX.conf` after init |
| **SSL** | **profile_09** (`e2e-collector-10` when `COLLECTOR_COUNT=10`): Postgres TLS with `sslmode=verify-full` + client certs |

Inspect a running collector:

```sh
docker exec e2e-collector-3 grep -E 'scan_commands|prefix|schedule' /etc/klouddbshield/kshieldconfig.toml
docker exec e2e-collector-3 psql -U shielduser -d shielddb -c "SELECT * FROM collector_profile_meta;"
docker exec e2e-collector-10 grep -E '^ssl' /etc/klouddbshield/kshieldconfig.toml
docker exec e2e-collector-10 psql -U shielduser -d shielddb -tAc "SHOW ssl;"
```

Rebuild after profile changes: `./run.sh down -v && ./run.sh`

```sh
# One-off
COLLECTOR_COUNT=5 ./run.sh

# Or edit .env, then recreate
./run.sh down -v
./run.sh
```

Stop / reset:

```sh
./run.sh down
./run.sh down -v    # also removes main-server SQLite volume
```

## Services

| Service | Role |
|---------|------|
| `main-server` | Dashboard + API on port **8081** |
| `main-server-db` | Optional central Postgres for main-server (`KSHIELD_DB_DRIVER=postgres`) |
| `collector` (×N) | Scaled by `COLLECTOR_COUNT` — Postgres 17 + `ciscollector` per container |

## Why scale instead of generated compose?

- **One service definition** in `docker-compose.yml` — no generated YAML
- **Standard Compose** `--scale` flag (no extra scripts)
- **Unique hosts** — entrypoint sets `APP_HOSTNAME` / `POSTGRES_HOST` from `hostname` per replica

## Configuration

Collector config is rendered at startup from `postgres-collector/kshieldconfig.toml.template` + env vars.

```toml
[postgres]
host = "<container-hostname>"   # unique per scaled replica
port = "5432"

[app]
hostname = "<container-hostname>"

[mainserver]
enabled = true
url = "http://main-server:8081"
token = "<matches server-node.yaml>"

[collector]
scan_commands = "postgres_cis,hba_scanner,pii_scanner"

[piiscanner]
run_option = "datascan"
database = "shielddb"
schema = "public"
```

**Cron:** `ciscollector --setup-cron` runs `scan_commands` on `COLLECTOR_SCHEDULE`. Optional separate crons:
- `[piiscanner].schedule` for `pii_scanner` (still list in `scan_commands`)
- `[collector.logparser].schedule` for log parser commands (`inactive_users`, `unique_ip`, `unused_lines`, `password_leak_scanner`)

An initial PII scan also runs at container start via `--piiscanner`.

## GUC drift (global baseline)

One fleet-wide golden baseline is seeded on **main-server** startup from `guc-baseline.json`:

```json
{
  "label": "e2e-global",
  "settings": { "ssl": "off", "logging_collector": "on", ... }
}
```

Collectors push live `SHOW ALL` snapshots on each scan (`guc_drift` is in default `SCAN_COMMANDS`). The dashboard **GUC Drift** page compares every host against this single baseline.

- **Matched:** `e2e-collector-1` (profile_00) — same `log_line_prefix` as baseline
- **Drift:** other profiles (different `log_line_prefix`); `e2e-collector-10` also drifts on `ssl=on`

Edit `docker_testing/e2e/guc-baseline.json` and restart main-server (or upload via the GUC Drift UI). Re-seed on a fresh volume:

```sh
./run.sh down -v && ./run.sh
curl -s http://localhost:8081/api/guc/baseline | python3 -m json.tool
curl -s http://localhost:8081/api/guc/drift | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('stats'))"
```

## Tuning (.env)

| Variable | Default | Purpose |
|----------|---------|---------|
| `COLLECTOR_COUNT` | `2` | Postgres+ciscollector replicas (profiles cycle 0–14) |
| `COLLECTOR_TOKEN` | (see file) | Shared auth with main-server |
| `COLLECTOR_SCHEDULE` | `*/5 * * * *` | Cron expression for all `scan_commands` |
| `SCAN_COMMANDS` | `postgres_cis,hba_scanner,pii_scanner,guc_drift,...` | Comma-separated collector jobs |
| `PII_RUN_OPTION` | `datascan` | `[piiscanner].run_option` (`datascan` needs no Python) |
| `PII_SCHEDULE` | (empty) | Optional `[piiscanner].schedule` — separate cron for PII only |
| `LOG_PARSER_SCHEDULE` | (empty) | Optional `[collector.logparser].schedule` for log parser commands |
| `LOG_PARSER_LOGFILE` | `/var/lib/postgresql/data/log/*.log` | `[collector.logparser].logfile` |
| `LOG_PARSER_HBAFILE` | `/var/lib/postgresql/data/pg_hba.conf` | `[collector.logparser].hbaconffile` |
| `LOG_PARSER_PREFIX` | `%t ` | `[collector.logparser].prefix` |
| `KSHIELD_DB_DRIVER` | `sqlite` | Main-server storage: `sqlite` or `postgres` |
| `MAIN_SERVER_DATABASE_URL` | (empty) | Postgres URL when driver is `postgres` |
| `server-node.yaml` `db_driver` | (empty) | File-based storage driver when env/CLI unset |
| `server-node.yaml` `postgres_url` | (empty) | File-based Postgres URL when env/CLI unset |
| `MAIN_SERVER_PG_USER` | `kshield` | `main-server-db` superuser |
| `MAIN_SERVER_PG_PASSWORD` | `kshield` | `main-server-db` password |
| `MAIN_SERVER_PG_DB` | `kshield` | `main-server-db` database name |

## Verify

```sh
./verify.sh
EXPECTED_COLLECTORS=3 EXPECTED_SCHEDULES=3 ./verify_schedules.sh
./verify_features.sh   # flow + schedules + all scan_commands features
./verify_profiles.sh   # distinct per-replica profiles (when COLLECTOR_COUNT >= 2)
./verify_all.sh        # same as verify_features.sh (full suite)
```

Manual checks:

```sh
curl -s http://localhost:8081/api/hosts
curl -s http://localhost:8081/api/collector/nodes
docker compose logs -f collector
```
