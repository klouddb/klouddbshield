package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	reprows "github.com/klouddb/klouddbshield/pkg/repository/rows"
)

const sqliteBusyTimeoutMs = 5000

// Repository implements repository.Repository using SQLite.
type Repository struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func (r *Repository) withWriteLock(fn func() error) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return fn()
}

func sqliteDSN(path string) string {
	return fmt.Sprintf("file:%s?mode=rwc&_busy_timeout=%d&_journal_mode=WAL&_txlock=immediate&_foreign_keys=on", path, sqliteBusyTimeoutMs)
}

// Open opens (or creates) the SQLite database at path.
func Open(ctx context.Context, path string) (*Repository, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	db.SetMaxOpenConns(32)
	db.SetMaxIdleConns(8)
	reportstore.RunsTable = "scan_results"
	repo := &Repository{db: db}
	if err := repo.EnsureSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return repo, nil
}

// FromDB wraps an existing SQLite connection (tests).
func FromDB(db *sql.DB) *Repository {
	reportstore.RunsTable = "scan_results"
	return &Repository{db: db}
}

func (r *Repository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *Repository) Close() error {
	return r.db.Close()
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	pragmas := `PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;`
	if _, err := r.db.ExecContext(ctx, pragmas); err != nil {
		return fmt.Errorf("sqlite pragmas: %w", err)
	}
	if err := ensureCollectorSchema(ctx, r.db); err != nil {
		return err
	}
	return reportstore.EnsureScanResultsSchema(ctx, r.db)
}

func (r *Repository) PersistScanResult(ctx context.Context, fileData map[string]interface{}, meta reportstore.ScanResultMeta) (string, error) {
	var id string
	err := r.withWriteLock(func() error {
		var err error
		id, err = reportstore.PersistScanResult(ctx, r.db, fileData, meta)
		return err
	})
	return id, err
}

func (r *Repository) PersistPIIReport(ctx context.Context, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error {
	return r.withWriteLock(func() error {
		return reportstore.PersistPIIReport(ctx, r.db, pg, piiJSON)
	})
}

func (r *Repository) PersistBackupComplianceReport(ctx context.Context, meta reportstore.BackupComplianceReportMeta, reportJSON map[string]interface{}) error {
	return r.withWriteLock(func() error {
		return reportstore.PersistBackupComplianceReport(ctx, r.db, meta, reportJSON)
	})
}

func (r *Repository) GetLatestRun(ctx context.Context, targetID string) (*reportstore.RunRow, error) {
	return reportstore.GetLatestRun(ctx, r.db, targetID)
}

func (r *Repository) GetLatestRunWithPII(ctx context.Context, targetID string) (*reportstore.RunRow, error) {
	return reportstore.GetLatestRunWithPII(ctx, r.db, targetID)
}

func (r *Repository) ListLatestBackupComplianceReports(ctx context.Context) ([]reportstore.BackupComplianceRow, error) {
	return reportstore.ListLatestBackupComplianceReports(ctx, r.db)
}

func (r *Repository) GetLatestRunWithBackupCompliance(ctx context.Context, targetID string) (*reportstore.BackupComplianceRow, error) {
	return reportstore.GetLatestRunWithBackupCompliance(ctx, r.db, targetID)
}

func (r *Repository) GetRunByID(ctx context.Context, id string) (*reportstore.RunRow, error) {
	return reportstore.GetRunByID(ctx, r.db, id)
}

func (r *Repository) GetRuns(ctx context.Context, limit int) ([]reportstore.RunRow, error) {
	return reportstore.GetRuns(ctx, r.db, limit)
}

func (r *Repository) ListRunTargetIDs(ctx context.Context) ([]string, error) {
	return reportstore.ListRunTargetIDs(ctx, r.db)
}

func (r *Repository) GetRunsForTarget(ctx context.Context, targetID string, limit int) ([]reportstore.RunRow, error) {
	return reportstore.GetRunsForTarget(ctx, r.db, targetID, limit)
}

func (r *Repository) UpsertGucBaseline(ctx context.Context, label string, settings map[string]string) error {
	return r.withWriteLock(func() error {
		return reportstore.UpsertGucBaseline(ctx, r.db, label, settings)
	})
}

func (r *Repository) GetGucBaseline(ctx context.Context) (string, map[string]string, string, error) {
	return reportstore.GetGucBaseline(ctx, r.db)
}

func (r *Repository) UpsertServerGucSnapshot(ctx context.Context, targetID, targetHost, nodeID string, settings map[string]string) error {
	return r.withWriteLock(func() error {
		return reportstore.UpsertServerGucSnapshot(ctx, r.db, targetID, targetHost, nodeID, settings)
	})
}

func (r *Repository) GetServerGucSnapshot(ctx context.Context, targetID string) (map[string]string, string, string, error) {
	return reportstore.GetServerGucSnapshot(ctx, r.db, targetID)
}

func (r *Repository) ListServerGucSnapshots(ctx context.Context) ([]reportstore.GucSnapshotSummary, error) {
	return reportstore.ListServerGucSnapshots(ctx, r.db)
}

func (r *Repository) UpsertGucIgnore(ctx context.Context, scope, targetID, gucName string) error {
	return r.withWriteLock(func() error {
		return reportstore.UpsertGucIgnore(ctx, r.db, scope, targetID, gucName)
	})
}

func (r *Repository) DeleteGucIgnore(ctx context.Context, scope, targetID, gucName string) error {
	return r.withWriteLock(func() error {
		return reportstore.DeleteGucIgnore(ctx, r.db, scope, targetID, gucName)
	})
}

func (r *Repository) ListGucIgnores(ctx context.Context) ([]reportstore.GucIgnoreEntry, error) {
	return reportstore.ListGucIgnores(ctx, r.db)
}

func (r *Repository) UpsertGucServerGroup(ctx context.Context, id, name, description string, baseline map[string]string) (string, error) {
	var out string
	err := r.withWriteLock(func() error {
		var err error
		out, err = reportstore.UpsertGucServerGroup(ctx, r.db, id, name, description, baseline)
		return err
	})
	return out, err
}

func (r *Repository) DeleteGucServerGroup(ctx context.Context, id string) error {
	return r.withWriteLock(func() error {
		return reportstore.DeleteGucServerGroup(ctx, r.db, id)
	})
}

func (r *Repository) GetGucServerGroup(ctx context.Context, id string) (*reportstore.GucServerGroup, error) {
	return reportstore.GetGucServerGroup(ctx, r.db, id)
}

func (r *Repository) ListGucServerGroups(ctx context.Context) ([]reportstore.GucServerGroup, error) {
	return reportstore.ListGucServerGroups(ctx, r.db)
}

func (r *Repository) SetGucServerGroupMembers(ctx context.Context, groupID string, targetIDs []string) error {
	return r.withWriteLock(func() error {
		return reportstore.SetGucServerGroupMembers(ctx, r.db, groupID, targetIDs)
	})
}

func (r *Repository) SetGucServerGroupBaseline(ctx context.Context, groupID string, baseline map[string]string) error {
	return r.withWriteLock(func() error {
		return reportstore.SetGucServerGroupBaseline(ctx, r.db, groupID, baseline)
	})
}

func (r *Repository) UpsertBackupCompliancePolicy(ctx context.Context, policy reportstore.BackupCompliancePolicyStored) error {
	return r.withWriteLock(func() error {
		return reportstore.UpsertBackupCompliancePolicy(ctx, r.db, policy)
	})
}

func (r *Repository) GetBackupCompliancePolicy(ctx context.Context) (reportstore.BackupCompliancePolicyStored, string, error) {
	return reportstore.GetBackupCompliancePolicy(ctx, r.db)
}

func (r *Repository) UpsertCollectorStatus(ctx context.Context, nodeID, hostname, ip string, ts time.Time, cronRunning bool, scheduledJobs int, lastError string) error {
	return r.withWriteLock(func() error {
		cronVal := 0
		if cronRunning {
			cronVal = 1
		}
		_, err := r.db.ExecContext(ctx, `
		INSERT INTO collector_status (
			node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_error, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			hostname = excluded.hostname,
			ip = excluded.ip,
			last_seen_at = excluded.last_seen_at,
			cron_running = excluded.cron_running,
			scheduled_jobs = excluded.scheduled_jobs,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at
	`, nodeID, hostname, strings.TrimSpace(ip), ts, cronVal, scheduledJobs,
			strings.TrimSpace(lastError), time.Now().UTC())
		return err
	})
}

func (r *Repository) InsertCollectorActivity(ctx context.Context, nodeID, kind, message, level string, ts time.Time) error {
	return r.withWriteLock(func() error {
		_, err := r.db.ExecContext(ctx, `
		INSERT INTO collector_activity (node_id, kind, message, level, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(kind), message, strings.TrimSpace(level), ts)
		return err
	})
}

func (r *Repository) TouchCollectorLastSeen(ctx context.Context, nodeID string, ts time.Time) error {
	return r.withWriteLock(func() error {
		_, err := r.db.ExecContext(ctx, `
		UPDATE collector_status SET last_seen_at = ?, updated_at = ? WHERE node_id = ?
	`, ts, time.Now().UTC(), nodeID)
		return err
	})
}

func (r *Repository) InsertCollectorLog(ctx context.Context, nodeID, level, message string, ts time.Time) error {
	return r.withWriteLock(func() error {
		_, err := r.db.ExecContext(ctx, `
		INSERT INTO collector_logs (node_id, level, message, created_at)
		VALUES (?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(level), message, ts)
		return err
	})
}

func (r *Repository) InsertCollectorRun(ctx context.Context, nodeID, hostname, trigger string, startedAt, finishedAt time.Time, features []string, success bool, errMsg string) error {
	return r.withWriteLock(func() error {
		featuresJSON, _ := json.Marshal(features)
		successVal := 0
		if success {
			successVal = 1
		}
		if _, err := r.db.ExecContext(ctx, `
		INSERT INTO collector_runs (node_id, trigger, started_at, finished_at, features, success, error)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(trigger), startedAt, finishedAt, string(featuresJSON), successVal, strings.TrimSpace(errMsg)); err != nil {
			return err
		}
		_, err := r.db.ExecContext(ctx, `
		INSERT INTO collector_status (node_id, hostname, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error, updated_at)
		VALUES (?, ?, ?, 0, 0, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			hostname = COALESCE(excluded.hostname, collector_status.hostname),
			last_seen_at = excluded.last_seen_at,
			last_run_at = excluded.last_run_at,
			last_error = CASE WHEN excluded.last_error != '' THEN excluded.last_error ELSE collector_status.last_error END,
			updated_at = excluded.updated_at
	`, nodeID, hostname, finishedAt, finishedAt, strings.TrimSpace(errMsg), time.Now().UTC())
		return err
	})
}

func (r *Repository) ListCollectorNodes(ctx context.Context) ([]reprows.CollectorNodeRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error
		FROM collector_status ORDER BY hostname ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCollectorNodes(rows)
}

func (r *Repository) GetCollectorNode(ctx context.Context, nodeID string) (*reprows.CollectorNodeRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error
		FROM collector_status WHERE node_id = ?
	`, nodeID)
	nodes, err := scanCollectorNodeRow(row)
	if err != nil {
		return nil, err
	}
	if nodes == nil {
		return nil, sql.ErrNoRows
	}
	return nodes, nil
}

func (r *Repository) ListCollectorRuns(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorRunRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, trigger, started_at, finished_at, features, success, error
		FROM collector_runs WHERE node_id = ? ORDER BY started_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCollectorRuns(rows)
}

func (r *Repository) ListCollectorActivity(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorActivityRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT kind, message, level, created_at FROM collector_activity
		WHERE node_id = ? ORDER BY created_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reprows.CollectorActivityRow
	for rows.Next() {
		var a reprows.CollectorActivityRow
		if err := rows.Scan(&a.Kind, &a.Message, &a.Level, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *Repository) ListCollectorLogs(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorLogRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT level, message, created_at FROM collector_logs
		WHERE node_id = ? ORDER BY created_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reprows.CollectorLogRow
	for rows.Next() {
		var row reprows.CollectorLogRow
		var level sql.NullString
		if err := rows.Scan(&level, &row.Message, &row.CreatedAt); err != nil {
			return nil, err
		}
		if level.Valid {
			row.Level = level.String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

const collectorSchemaSQL = `
CREATE TABLE IF NOT EXISTS collector_status (
	node_id TEXT PRIMARY KEY,
	hostname TEXT NOT NULL,
	ip TEXT,
	last_seen_at DATETIME NOT NULL,
	cron_running INTEGER NOT NULL DEFAULT 0,
	scheduled_jobs INTEGER NOT NULL DEFAULT 0,
	last_run_at DATETIME,
	last_error TEXT,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS collector_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_id TEXT NOT NULL,
	trigger TEXT NOT NULL,
	started_at DATETIME NOT NULL,
	finished_at DATETIME,
	features TEXT,
	success INTEGER NOT NULL DEFAULT 0,
	error TEXT,
	FOREIGN KEY(node_id) REFERENCES collector_status(node_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_collector_runs_node_started
ON collector_runs(node_id, started_at DESC);

CREATE TABLE IF NOT EXISTS collector_activity (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	message TEXT NOT NULL,
	level TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(node_id) REFERENCES collector_status(node_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_collector_activity_node_created
ON collector_activity(node_id, created_at DESC);

CREATE TABLE IF NOT EXISTS collector_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	node_id TEXT NOT NULL,
	level TEXT,
	message TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(node_id) REFERENCES collector_status(node_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_collector_logs_node_created
ON collector_logs(node_id, created_at DESC);
`

func ensureCollectorSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, collectorSchemaSQL)
	return err
}
