#!/bin/bash
set -euo pipefail

# Per-replica seed data (COLLECTOR_PROFILE_* set in entrypoint before postgres init).
idx="${COLLECTOR_PROFILE_INDEX:-0}"
profile_id="${COLLECTOR_PROFILE_ID:-profile_$(printf '%02d' "${idx}")}"
focus="${COLLECTOR_FOCUS_TABLES:-users,contacts}"
replica="${COLLECTOR_REPLICA_INDEX:-1}"

# Migrations insert explicit PKs; bump serial sequences before profile seed rows.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  SELECT setval(pg_get_serial_sequence('users', 'user_id'), COALESCE((SELECT MAX(user_id) FROM users), 1));
  SELECT setval(pg_get_serial_sequence('contacts', 'contact_id'), COALESCE((SELECT MAX(contact_id) FROM contacts), 1));
  SELECT setval(pg_get_serial_sequence('employees', 'employee_id'), COALESCE((SELECT MAX(employee_id) FROM employees), 1));
  SELECT setval(pg_get_serial_sequence('orders', 'order_id'), COALESCE((SELECT MAX(order_id) FROM orders), 1));
  SELECT setval(pg_get_serial_sequence('devices', 'device_id'), COALESCE((SELECT MAX(device_id) FROM devices), 1));
  SELECT setval(pg_get_serial_sequence('sessions', 'session_id'), COALESCE((SELECT MAX(session_id) FROM sessions), 1));
  SELECT setval(pg_get_serial_sequence('customers', 'customer_id'), COALESCE((SELECT MAX(customer_id) FROM customers), 1));
  SELECT setval(pg_get_serial_sequence('logs', 'log_id'), COALESCE((SELECT MAX(log_id) FROM logs), 1));
  SELECT setval(pg_get_serial_sequence('credentials', 'credential_id'), COALESCE((SELECT MAX(credential_id) FROM credentials), 1));
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE TABLE IF NOT EXISTS collector_profile_meta (
    profile_id TEXT PRIMARY KEY,
    replica_index INT NOT NULL,
    focus_tables TEXT NOT NULL,
    seeded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  INSERT INTO collector_profile_meta (profile_id, replica_index, focus_tables)
  VALUES ('${profile_id}', ${replica}, '${focus}')
  ON CONFLICT (profile_id) DO UPDATE
    SET replica_index = EXCLUDED.replica_index,
        focus_tables = EXCLUDED.focus_tables,
        seeded_at = NOW();

  CREATE SCHEMA IF NOT EXISTS ${profile_id};

  CREATE TABLE IF NOT EXISTS ${profile_id}.inventory (
    item_id SERIAL PRIMARY KEY,
    sku TEXT NOT NULL,
    owner_email TEXT,
    notes TEXT
  );

  CREATE TABLE IF NOT EXISTS ${profile_id}.audit_trail (
    event_id SERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  TRUNCATE ${profile_id}.inventory, ${profile_id}.audit_trail RESTART IDENTITY;
EOSQL

# Profile-specific rows in dedicated schema tables.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  INSERT INTO ${profile_id}.inventory (sku, owner_email, notes) VALUES
    ('SKU-${profile_id}-001', '${profile_id}@collector.e2e', 'replica ${replica} seed A'),
    ('SKU-${profile_id}-002', '${profile_id}-ops@collector.e2e', 'replica ${replica} seed B'),
    ('SKU-${profile_id}-003', '${profile_id}-audit@collector.e2e', 'replica ${replica} seed C');

  INSERT INTO ${profile_id}.audit_trail (actor, action, payload) VALUES
    ('${profile_id}', 'bootstrap', jsonb_build_object('replica', ${replica}, 'focus', '${focus}')),
    ('${profile_id}', 'profile_ready', jsonb_build_object('tables', '${focus}'));
EOSQL

# Tag focus tables with profile-specific rows (public schema — shared migrations stay intact).
IFS=',' read -r -a tables <<< "${focus}"
for table in "${tables[@]}"; do
  table="$(echo "${table}" | xargs)"
  [ -n "${table}" ] || continue
  case "${table}" in
    users)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO users (name, username, user_email, gender, nationality)
        VALUES ('${profile_id} User', '${profile_id}_user', '${profile_id}@users.e2e', 'N/A', 'E2E')
        ON CONFLICT (username) DO NOTHING;
EOSQL
      ;;
    contacts)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO contacts (full_name, mobile_number, email_address, home_address, postal_code)
        VALUES ('${profile_id} Contact', '555-${replica}000', '${profile_id}@contacts.e2e', 'Profile ${idx} Lane', 'E2E-${idx}');
EOSQL
      ;;
    employees)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO employees (employee_name, ssn, birth_date, address, phone_number)
        VALUES ('${profile_id} Employee', '999-${idx}-0001', '1990-01-01', 'Profile ${idx}', '555-${replica}001')
        ON CONFLICT (ssn) DO NOTHING;
EOSQL
      ;;
    orders)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO orders (user_id, credit_card, po_box, order_date)
        SELECT user_id, '4111-1111-1111-${idx}${replica}', 'PO-${profile_id}', NOW()
        FROM users WHERE username = '${profile_id}_user' LIMIT 1;
EOSQL
      ;;
    devices)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO devices (user_id, ip_address, mac_address, location_info)
        SELECT user_id, '10.${idx}.${replica}.1', 'aa:bb:cc:dd:${idx}:${replica}', '${profile_id} datacenter'
        FROM users WHERE username = '${profile_id}_user' LIMIT 1;
EOSQL
      ;;
    sessions)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO sessions (user_id, oauth_token, session_ip, login_time, logout_time)
        SELECT user_id, 'token-${profile_id}', '10.${idx}.${replica}.2', NOW() - interval '1 hour', NOW()
        FROM users WHERE username = '${profile_id}_user' LIMIT 1;
EOSQL
      ;;
    customers)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO customers (customer_name, phone, email, customer_address, zip_code, card_number)
        VALUES ('${profile_id} Customer', '555-${replica}002', '${profile_id}@customers.e2e', 'Profile ${idx} Ave', 'ZIP-${idx}', '5500-0000-0000-${idx}${replica}');
EOSQL
      ;;
    logs)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO logs (user_id, action_by, action_email, action_description, log_time)
        SELECT user_id, '${profile_id}', '${profile_id}@logs.e2e', 'profile ${idx} bootstrap', NOW()
        FROM users WHERE username = '${profile_id}_user' LIMIT 1;
EOSQL
      ;;
    credentials)
      psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        INSERT INTO credentials (user_id, user_password, email, user_fullname)
        SELECT user_id, 'hash-${profile_id}', '${profile_id}@credentials.e2e', '${profile_id} Service'
        FROM users WHERE username = '${profile_id}_user' LIMIT 1;
EOSQL
      ;;
  esac
done

echo "profile data ready: ${profile_id} (replica ${replica}, focus: ${focus})"
