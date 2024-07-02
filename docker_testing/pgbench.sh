#!/bin/bash
set -e

echo "processing users: $PGUSERS"

# Read the environment variable into an array
IFS=',' read -ra PGUSERS <<< "$PGUSERS"

for user in "${PGUSERS[@]}"; do
# -T 100: run for 100 seconds
PGPASSWORD=password pgbench -T $TIME -U "$user" -h postgres -p 5432 -d postgres

# adding multiline queries to validate if that scenario works as expected
PGPASSWORD=password psql -U "$user" -h postgres -p 5432 -d postgres -c "SELECT t.*
FROM pgbench_tellers t
WHERE tbalance = (
  SELECT max(tbalance)
  FROM pgbench_tellers
  WHERE bid = t.bid
);
"

PGPASSWORD=password psql -U "$user" -h postgres -p 5432 -d postgres -c "SELECT b.bid, sum(t.tbalance) total_balance
FROM pgbench_tellers t
JOIN pgbench_branches b ON t.bid = b.bid
GROUP BY b.bid;"

done

PGPASSWORD=password psql -U "$user" -h postgres -p 5432 -d postgres -c "select pg_panic();"
