#!/bin/bash
set -e

# Function to setup log line prefix
setup_logline() {
    # Check if postgresql.conf file exists and logging_collector is already set to on
    if [[ -f "$PGDATA/postgresql.conf" ]]; then
        return
    fi

    # Wait for PostgreSQL to start
    until pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" > /dev/null 2>&1; do
        echo "Waiting for PostgreSQL to start..."
        sleep 1
    done

    # Configure log_line_prefix
    echo "log_line_prefix = '$PREFIX'" >> "$PGDATA/postgresql.conf"
    echo "logging_collector = on" >> "$PGDATA/postgresql.conf"
    echo "log_min_duration_statement=0" >> "$PGDATA/postgresql.conf"
    echo "log_statement='all'" >> "$PGDATA/postgresql.conf"
    echo "log_directory = '/var/log/postgresql'" >> "$PGDATA/postgresql.conf"
    echo "log_rotation_size = $FILE_SIZE" >> "$PGDATA/postgresql.conf"
    echo "log_connections = yes" >> "$PGDATA/postgresql.conf"

    cat "$PGDATA/postgresql.conf"

    # Restart PostgreSQL
    exec pg_ctl restart -w
}

# Execute the log line setup function
setup_logline &
sleep 1

# Execute the default entrypoint script
exec /usr/local/bin/docker-entrypoint.sh "$@"
