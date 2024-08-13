package calctransactions

const Autovacuum_alerts_query = `
WITH max_age AS (
    SELECT 2000000000 as max_old_xid
        , setting AS autovacuum_freeze_max_age
        FROM pg_catalog.pg_settings
        WHERE name = 'autovacuum_freeze_max_age' )
, per_database_stats AS (
    SELECT datname
        , m.max_old_xid::int
        , m.autovacuum_freeze_max_age::int
        , age(d.datfrozenxid) AS oldest_current_xid
    FROM pg_catalog.pg_database d
    JOIN max_age m ON (true)
    WHERE d.datallowconn )
SELECT max(oldest_current_xid) AS oldest_current_xid
    , max(ROUND(100*(oldest_current_xid/max_old_xid::float))) AS percent_towards_wraparound
    , max(ROUND(100*(oldest_current_xid/autovacuum_freeze_max_age::float))) AS percent_towards_emergency_autovac
FROM per_database_stats;
`

const GET_DATABASE_STATS = `
SELECT datname
    , age(datfrozenxid)
    , current_setting('autovacuum_freeze_max_age')
FROM pg_database
ORDER BY 2 DESC LIMIT 5;
`

const GET_TABLE_STATS = `
SELECT c.oid::regclass
    , age(c.relfrozenxid)
    , pg_size_pretty(pg_total_relation_size(c.oid))
FROM pg_class c
JOIN pg_namespace n on c.relnamespace = n.oid
WHERE relkind IN ('r', 't', 'm')
AND n.nspname NOT IN ('pg_toast')
ORDER BY 2 DESC LIMIT 5;
`

const GET_CURRENT_TX_ID = `select txid_current();`

const GET_TXID_AGE_DETAILS = `WITH q AS (
SELECT
  (SELECT max(age(backend_xmin))
      FROM pg_stat_activity  WHERE state != 'idle' )       AS oldest_running_xact_age,
  (SELECT max(age(transaction)) FROM pg_prepared_xacts)    AS oldest_prepared_xact_age,
  (SELECT max(greatest(age(catalog_xmin),age(xmin))) FROM pg_replication_slots)        AS oldest_replication_slot_age,
  (SELECT max(age(backend_xmin)) FROM pg_stat_replication) AS oldest_replica_xact_age
)
SELECT *,
       2^31 - oldest_running_xact_age AS oldest_running_xact_left,
       2^31 - oldest_prepared_xact_age AS oldest_prepared_xact_left,
       2^31 - oldest_replication_slot_age AS oldest_replication_slot_left,
       2^31 - oldest_replica_xact_age AS oldest_replica_xact_left
FROM q;`
