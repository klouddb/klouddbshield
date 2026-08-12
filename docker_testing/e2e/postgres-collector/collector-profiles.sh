#!/bin/bash
# Per-replica collector profiles (15 variants). Replica index comes from hostname
# (e.g. e2e-collector-3 → profile index 2). Override with COLLECTOR_PROFILE_INDEX.

COLLECTOR_PROFILE_COUNT="${COLLECTOR_PROFILE_COUNT:-15}"

extract_replica_index() {
  local host="${1:-$(hostname -f 2>/dev/null || hostname)}"
  if [[ "${host}" =~ collector-([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${host}" =~ -([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo "1"
}

# Compose scale sets hostname to the container ID, not e2e-collector-N. Read compose
# labels via the mounted Docker socket (local e2e only) for stable replica identity.
resolve_container_identity() {
  [ -n "${COLLECTOR_IDENTITY_RESOLVED:-}" ] && return 0

  local cid="${1:-$(hostname)}"
  export APP_HOSTNAME="${APP_HOSTNAME:-${cid}}"
  export POSTGRES_HOST="${POSTGRES_HOST:-${APP_HOSTNAME}}"
  export COLLECTOR_REPLICA_INDEX="${COLLECTOR_REPLICA_INDEX:-$(extract_replica_index "${APP_HOSTNAME}")}"

  if [ -S /var/run/docker.sock ]; then
    local json num project service
    json="$(curl -sf --unix-socket /var/run/docker.sock "http://localhost/containers/${cid}/json" 2>/dev/null || true)"
    if [ -n "${json}" ]; then
      num="$(printf '%s' "${json}" | tr ',' '\n' | grep 'com.docker.compose.container-number' | head -1 | sed -n 's/.*"com.docker.compose.container-number":"\([0-9]*\)".*/\1/p')"
      project="$(printf '%s' "${json}" | tr ',' '\n' | grep '"com.docker.compose.project"' | head -1 | sed -n 's/.*"com.docker.compose.project":"\([^"]*\)".*/\1/p')"
      service="$(printf '%s' "${json}" | tr ',' '\n' | grep '"com.docker.compose.service"' | head -1 | sed -n 's/.*"com.docker.compose.service":"\([^"]*\)".*/\1/p')"
      if [ -n "${num}" ] && [ -n "${project}" ] && [ -n "${service}" ]; then
        export COLLECTOR_REPLICA_INDEX="${num}"
        export APP_HOSTNAME="${project}-${service}-${num}"
        export POSTGRES_HOST="${APP_HOSTNAME}"
      fi
    fi
  fi

  export COLLECTOR_IDENTITY_RESOLVED=1
}

apply_collector_profile() {
  local replica_idx profile_idx
  replica_idx="$(extract_replica_index)"
  replica_idx="${COLLECTOR_REPLICA_INDEX:-${replica_idx}}"

  if [ -n "${COLLECTOR_PROFILE_INDEX:-}" ]; then
    profile_idx="${COLLECTOR_PROFILE_INDEX}"
  else
    profile_idx=$(( (replica_idx - 1) % COLLECTOR_PROFILE_COUNT ))
  fi

  export COLLECTOR_REPLICA_INDEX="${replica_idx}"
  export COLLECTOR_PROFILE_INDEX="${profile_idx}"
  export COLLECTOR_PROFILE_ID="profile_$(printf '%02d' "${profile_idx}")"

  export COLLECTOR_SSL_ENABLED="false"
  export POSTGRES_SSLMODE="disable"
  export POSTGRES_SSLCERT=""
  export POSTGRES_SSLKEY=""
  export POSTGRES_SSLROOTCERT=""

  # Defaults from .env / compose can be overridden per profile below.
  local base_scan="${SCAN_COMMANDS:-postgres_cis,hba_scanner,pii_scanner,ssl_audit,inactive_users,unique_ip,unused_lines,password_leak_scanner}"
  local base_schedule="${COLLECTOR_SCHEDULE:-*/5 * * * *}"
  local base_pii="${PII_RUN_OPTION:-datascan}"
  local base_pii_sched="${PII_SCHEDULE:-0 3 * * 0}"
  local base_log_sched="${LOG_PARSER_SCHEDULE:-0 4 * * *}"
  local base_log_prefix="${LOG_PARSER_PREFIX:-%t %u %d %h }"

  case "${profile_idx}" in
    0)
      export SCAN_COMMANDS="${base_scan}"
      export COLLECTOR_SCHEDULE="*/5 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="0 2 * * 0"
      export LOG_PARSER_SCHEDULE="0 3 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h "
      export LOG_PARSER_PREFIX="%t %u %d %h "
      export COLLECTOR_FOCUS_TABLES="users,contacts"
      export COLLECTOR_PGBENCH_SCALE="10"
      export COLLECTOR_EXTRA_USERS="6"
      ;;
    1)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,inactive_users,unique_ip"
      export COLLECTOR_SCHEDULE="*/7 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="15 1 * * 1"
      export LOG_PARSER_SCHEDULE="30 2 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%m [%p] %u@%d "
      export LOG_PARSER_PREFIX="%m [%p] %u@%d "
      export COLLECTOR_FOCUS_TABLES="employees,orders"
      export COLLECTOR_PGBENCH_SCALE="5"
      export COLLECTOR_EXTRA_USERS="4"
      ;;
    2)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,unused_lines,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/10 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="0 4 * * 2"
      export LOG_PARSER_SCHEDULE="0 5 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t [%p]: %u %d %h "
      export LOG_PARSER_PREFIX="%t [%p]: %u %d %h "
      export COLLECTOR_FOCUS_TABLES="devices,sessions"
      export COLLECTOR_PGBENCH_SCALE="15"
      export COLLECTOR_EXTRA_USERS="8"
      ;;
    3)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,inactive_users,unique_ip,unused_lines"
      export COLLECTOR_SCHEDULE="*/12 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="45 2 * * 3"
      export LOG_PARSER_SCHEDULE="15 3 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %a "
      export LOG_PARSER_PREFIX="%t %u %d %a "
      export COLLECTOR_FOCUS_TABLES="customers,logs"
      export COLLECTOR_PGBENCH_SCALE="8"
      export COLLECTOR_EXTRA_USERS="3"
      ;;
    4)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,ssl_audit,pii_scanner,inactive_users,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/15 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="0 1 * * 4"
      export LOG_PARSER_SCHEDULE="0 6 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u@%d [%h] "
      export LOG_PARSER_PREFIX="%t %u@%d [%h] "
      export COLLECTOR_FOCUS_TABLES="users,credentials"
      export COLLECTOR_PGBENCH_SCALE="20"
      export COLLECTOR_EXTRA_USERS="10"
      ;;
    5)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,unique_ip,unused_lines"
      export COLLECTOR_SCHEDULE="*/6 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="30 3 * * 5"
      export LOG_PARSER_SCHEDULE="30 4 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %e "
      export LOG_PARSER_PREFIX="%t %u %d %h %e "
      export COLLECTOR_FOCUS_TABLES="contacts,customers"
      export COLLECTOR_PGBENCH_SCALE="12"
      export COLLECTOR_EXTRA_USERS="5"
      ;;
    6)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,inactive_users,unique_ip,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/8 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="0 0 * * 6"
      export LOG_PARSER_SCHEDULE="0 7 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %c "
      export LOG_PARSER_PREFIX="%t %u %d %h %c "
      export COLLECTOR_FOCUS_TABLES="orders,devices"
      export COLLECTOR_PGBENCH_SCALE="6"
      export COLLECTOR_EXTRA_USERS="7"
      ;;
    7)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,ssl_audit,inactive_users,unique_ip,unused_lines,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/9 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="15 4 * * 0"
      export LOG_PARSER_SCHEDULE="15 5 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %l "
      export LOG_PARSER_PREFIX="%t %u %d %h %l "
      export COLLECTOR_FOCUS_TABLES="employees,sessions"
      export COLLECTOR_PGBENCH_SCALE="18"
      export COLLECTOR_EXTRA_USERS="2"
      ;;
    8)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,inactive_users,unused_lines"
      export COLLECTOR_SCHEDULE="*/11 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="30 5 * * 1"
      export LOG_PARSER_SCHEDULE="30 6 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %x "
      export LOG_PARSER_PREFIX="%t %u %d %h %x "
      export COLLECTOR_FOCUS_TABLES="logs,credentials"
      export COLLECTOR_PGBENCH_SCALE="9"
      export COLLECTOR_EXTRA_USERS="9"
      ;;
    9)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,unique_ip,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/13 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="0 2 * * 2"
      export LOG_PARSER_SCHEDULE="0 8 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %v "
      export LOG_PARSER_PREFIX="%t %u %d %h %v "
      export COLLECTOR_FOCUS_TABLES="users,orders"
      export COLLECTOR_PGBENCH_SCALE="14"
      export COLLECTOR_EXTRA_USERS="6"
      export COLLECTOR_SSL_ENABLED="true"
      export POSTGRES_SSLMODE="verify-full"
      export POSTGRES_SSLCERT="/etc/klouddbshield/certs/client.crt"
      export POSTGRES_SSLKEY="/etc/klouddbshield/certs/client.key"
      export POSTGRES_SSLROOTCERT="/etc/klouddbshield/certs/ca.crt"
      ;;
    10)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,inactive_users,unique_ip,unused_lines"
      export COLLECTOR_SCHEDULE="*/14 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="45 1 * * 3"
      export LOG_PARSER_SCHEDULE="45 2 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %q "
      export LOG_PARSER_PREFIX="%t %u %d %h %q "
      export COLLECTOR_FOCUS_TABLES="customers,sessions"
      export COLLECTOR_PGBENCH_SCALE="11"
      export COLLECTOR_EXTRA_USERS="4"
      ;;
    11)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,ssl_audit,pii_scanner,unique_ip,unused_lines,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/16 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="0 3 * * 4"
      export LOG_PARSER_SCHEDULE="0 9 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %s "
      export LOG_PARSER_PREFIX="%t %u %d %h %s "
      export COLLECTOR_FOCUS_TABLES="contacts,devices"
      export COLLECTOR_PGBENCH_SCALE="7"
      export COLLECTOR_EXTRA_USERS="8"
      ;;
    12)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,inactive_users,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/17 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="15 2 * * 5"
      export LOG_PARSER_SCHEDULE="15 4 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %b "
      export LOG_PARSER_PREFIX="%t %u %d %h %b "
      export COLLECTOR_FOCUS_TABLES="employees,credentials"
      export COLLECTOR_PGBENCH_SCALE="16"
      export COLLECTOR_EXTRA_USERS="3"
      ;;
    13)
      export SCAN_COMMANDS="postgres_cis,hba_scanner,pii_scanner,ssl_audit,inactive_users,unique_ip,password_leak_scanner"
      export COLLECTOR_SCHEDULE="*/18 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="30 0 * * 6"
      export LOG_PARSER_SCHEDULE="30 1 * * *"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %m "
      export LOG_PARSER_PREFIX="%t %u %d %h %m "
      export COLLECTOR_FOCUS_TABLES="orders,logs"
      export COLLECTOR_PGBENCH_SCALE="13"
      export COLLECTOR_EXTRA_USERS="5"
      ;;
    14)
      export SCAN_COMMANDS="${base_scan}"
      export COLLECTOR_SCHEDULE="*/20 * * * *"
      export PII_RUN_OPTION="datascan"
      export PII_SCHEDULE="${base_pii_sched}"
      export LOG_PARSER_SCHEDULE="${base_log_sched}"
      export COLLECTOR_LOG_LINE_PREFIX="%t %u %d %h %p "
      export LOG_PARSER_PREFIX="%t %u %d %h %p "
      export COLLECTOR_FOCUS_TABLES="users,employees,customers"
      export COLLECTOR_PGBENCH_SCALE="25"
      export COLLECTOR_EXTRA_USERS="12"
      ;;
    *)
      export SCAN_COMMANDS="${base_scan}"
      export COLLECTOR_SCHEDULE="${base_schedule}"
      export PII_RUN_OPTION="${base_pii}"
      export PII_SCHEDULE="${base_pii_sched}"
      export LOG_PARSER_SCHEDULE="${base_log_sched}"
      export COLLECTOR_LOG_LINE_PREFIX="${base_log_prefix}"
      export LOG_PARSER_PREFIX="${base_log_prefix}"
      export COLLECTOR_FOCUS_TABLES="users,contacts"
      export COLLECTOR_PGBENCH_SCALE="10"
      export COLLECTOR_EXTRA_USERS="6"
      ;;
  esac

  export COLLECTOR_HBA_SNIPPET="/app/hba/profile-$(printf '%02d' "${profile_idx}").conf"
  export LOG_PARSER_HBAFILE="${LOG_PARSER_HBAFILE:-/var/lib/postgresql/data/pg_hba.conf}"
}
