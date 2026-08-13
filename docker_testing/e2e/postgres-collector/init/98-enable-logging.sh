#!/bin/bash
set -euo pipefail
# Enable CSV logging for logparser e2e (runs once during postgres initdb).
# log_line_prefix is set per replica via collector-profiles.sh → COLLECTOR_LOG_LINE_PREFIX.
prefix="${COLLECTOR_LOG_LINE_PREFIX:-%t %u %d %h }"
cat >> "${PGDATA}/postgresql.conf" <<EOF
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_connections = on
log_disconnections = on
log_line_prefix = '${prefix}'
EOF
mkdir -p "${PGDATA}/log"
