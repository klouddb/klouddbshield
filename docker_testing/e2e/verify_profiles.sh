#!/bin/bash
set -euo pipefail

# Verify scaled collectors received distinct profiles (config, data, log prefix, HBA).
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${ROOT}"

read_env_var() {
  local key="$1"
  [ -f .env ] || return 0
  local line
  line="$(grep -E "^${key}=" .env | tail -1 || true)"
  [ -n "${line}" ] || return 0
  echo "${line#*=}" | tr -d '"'
}

MIN_COLLECTORS="${MIN_COLLECTORS:-${COLLECTOR_COUNT:-$(read_env_var COLLECTOR_COUNT)}}"
MIN_COLLECTORS="${MIN_COLLECTORS:-2}"
MIN_UNIQUE_PROFILES="${MIN_UNIQUE_PROFILES:-2}"

collectors="$(docker ps --filter name=collector --format '{{.Names}}' | sort)"
count="$(printf '%s\n' "${collectors}" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "${count}" -lt "${MIN_COLLECTORS}" ]; then
  echo "FAIL: expected at least ${MIN_COLLECTORS} collector containers, found ${count}" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

while IFS= read -r c; do
  [ -n "${c}" ] || continue
  prefix="$(docker exec "${c}" grep -E '^prefix = ' /etc/klouddbshield/kshieldconfig.toml 2>/dev/null | head -1 || true)"
  scan="$(docker exec "${c}" grep -E '^scan_commands = ' /etc/klouddbshield/kshieldconfig.toml 2>/dev/null | head -1 || true)"
  profile="$(docker exec "${c}" psql -U shielduser -d shielddb -tAc 'SELECT profile_id FROM collector_profile_meta LIMIT 1;' 2>/dev/null | tr -d ' ' || true)"
  hba_tag="$(docker exec "${c}" grep -c 'e2e profile profile_' /var/lib/postgresql/data/pg_hba.conf 2>/dev/null || echo 0)"

  echo "${c}: profile=${profile:-unknown} prefix=${prefix} hba_rules=${hba_tag}"
  printf '%s\n' "${profile}" >> "${tmp}.profiles"
  printf '%s\n' "${prefix}" >> "${tmp}.prefixes"
  printf '%s\n' "${scan}" >> "${tmp}.scans"
done <<< "${collectors}"

unique_profiles="$(grep -v '^$' "${tmp}.profiles" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
unique_prefix="$(grep -v '^$' "${tmp}.prefixes" 2>/dev/null | sort -u | wc -l | tr -d ' ')"

if [ "${count}" -ge 2 ] && [ "${unique_profiles}" -lt "${MIN_UNIQUE_PROFILES}" ]; then
  echo "FAIL: expected >= ${MIN_UNIQUE_PROFILES} unique collector_profile_meta rows, got ${unique_profiles}" >&2
  exit 1
fi

if [ "${count}" -ge 2 ] && [ "${unique_prefix}" -lt "${MIN_UNIQUE_PROFILES}" ]; then
  echo "FAIL: expected >= ${MIN_UNIQUE_PROFILES} unique log prefixes, got ${unique_prefix}" >&2
  exit 1
fi

echo ""
echo "PASS: ${count} collector(s), ${unique_profiles} unique profile(s), ${unique_prefix} unique log prefix(es)"
