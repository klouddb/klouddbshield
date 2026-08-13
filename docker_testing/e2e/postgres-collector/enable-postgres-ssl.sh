#!/bin/bash
set -euo pipefail

# Generate Postgres server + client TLS material when profile enables SSL (local e2e only).
[ "${COLLECTOR_SSL_ENABLED:-false}" = "true" ] || exit 0

pgdata="${PGDATA:-/var/lib/postgresql/data}"
cert_dir="/etc/klouddbshield/certs"
ssl_dir="${pgdata}/ssl"
host="${POSTGRES_HOST:-localhost}"
user="${POSTGRES_USER:-shielduser}"

if [ -f "${pgdata}/postgresql.conf" ] && grep -qE '^ssl[[:space:]]*=[[:space:]]*on' "${pgdata}/postgresql.conf"; then
  echo "postgres SSL already enabled for ${host}"
  exit 0
fi

mkdir -p "${cert_dir}" "${ssl_dir}"
chmod 700 "${cert_dir}" "${ssl_dir}"

openssl req -new -x509 -days 3650 -nodes -text \
  -out "${cert_dir}/ca.crt" -keyout "${cert_dir}/ca.key" \
  -subj "/CN=e2e-collector-ca" >/dev/null 2>&1

openssl req -new -nodes -text \
  -out /tmp/server.csr -keyout "${ssl_dir}/server.key" \
  -subj "/CN=${host}" >/dev/null 2>&1

cat > /tmp/server.ext <<EOF
subjectAltName=DNS:${host},DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in /tmp/server.csr -text -days 3650 \
  -CA "${cert_dir}/ca.crt" -CAkey "${cert_dir}/ca.key" -CAcreateserial \
  -out "${ssl_dir}/server.crt" -extfile /tmp/server.ext >/dev/null 2>&1

openssl req -new -nodes -text \
  -out /tmp/client.csr -keyout "${cert_dir}/client.key" \
  -subj "/CN=${user}" >/dev/null 2>&1

openssl x509 -req -in /tmp/client.csr -text -days 3650 \
  -CA "${cert_dir}/ca.crt" -CAkey "${cert_dir}/ca.key" -CAcreateserial \
  -out "${cert_dir}/client.crt" >/dev/null 2>&1

chmod 600 "${cert_dir}/ca.key" "${cert_dir}/client.key" "${ssl_dir}/server.key"
chmod 644 "${cert_dir}/ca.crt" "${cert_dir}/client.crt" "${ssl_dir}/server.crt"
chown -R postgres:postgres "${ssl_dir}"
chown -R root:root "${cert_dir}"
chmod 755 "${cert_dir}"

cat >> "${pgdata}/postgresql.conf" <<EOF
ssl = on
ssl_cert_file = '${ssl_dir}/server.crt'
ssl_key_file = '${ssl_dir}/server.key'
EOF

echo "postgres SSL configured for ${host} (certs in ${cert_dir})"
