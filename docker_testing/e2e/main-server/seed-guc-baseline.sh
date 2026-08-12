#!/bin/bash
set -euo pipefail

BASE_URL="${GUC_BASELINE_URL:-http://127.0.0.1:8081}"
BASELINE_FILE="${GUC_BASELINE_FILE:-/app/guc-baseline.json}"
TIMEOUT_SEC="${GUC_BASELINE_SEED_TIMEOUT_SEC:-120}"

json_key_count() {
  local blob="$1"
  local count
  count="$(printf '%s' "${blob}" | sed -n 's/.*"key_count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)"
  printf '%s' "${count:-0}"
}

if [ ! -f "${BASELINE_FILE}" ]; then
  echo "GUC baseline seed skipped: ${BASELINE_FILE} not found" >&2
  exit 0
fi

deadline=$((SECONDS + TIMEOUT_SEC))
until curl -sf "${BASE_URL%/}/api/overview" >/dev/null 2>&1; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "GUC baseline seed timed out waiting for main-server" >&2
    exit 1
  fi
  sleep 1
done

existing="$(curl -sf "${BASE_URL%/}/api/guc/baseline" || echo '{"key_count":0}')"
existing_keys="$(json_key_count "${existing}")"

if [ "${existing_keys}" -gt 0 ]; then
  echo "GUC baseline already present (${existing_keys} keys); skipping seed"
  exit 0
fi

echo "Seeding global GUC baseline from ${BASELINE_FILE}..."
curl -sf -X PUT "${BASE_URL%/}/api/guc/baseline" \
  -H "Content-Type: application/json" \
  --data-binary "@${BASELINE_FILE}" >/dev/null

seeded="$(curl -sf "${BASE_URL%/}/api/guc/baseline")"
seeded_keys="$(json_key_count "${seeded}")"
label="$(sed -n 's/.*"label"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${BASELINE_FILE}" | head -1)"
echo "GUC baseline ready: label=${label:-e2e-global} keys=${seeded_keys}"
