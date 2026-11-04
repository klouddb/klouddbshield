package reportstore

// RunsTable is the SQLite table used for scan result rows (runs or scan_results).
var RunsTable = "runs"

// UsePostgresPlaceholders is set by the Postgres repository on Open so
// shared reportstore SQL can rebind ? to $1 without changing SQLite.
var UsePostgresPlaceholders bool
