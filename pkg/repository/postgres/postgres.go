package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	reprows "github.com/klouddb/klouddbshield/pkg/repository/rows"
)

// Repository implements repository.Repository using PostgreSQL.
type Repository struct {
	db *sql.DB
}

// Open connects to PostgreSQL and ensures schema.
func Open(ctx context.Context, url string) (*Repository, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	// Shared reportstore queries use RunsTable; Postgres schema is scan_results (not runs).
	reportstore.RunsTable = "scan_results"
	reportstore.UsePostgresPlaceholders = true
	repo := &Repository{db: db}
	if err := repo.EnsureSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return repo, nil
}

func (r *Repository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *Repository) Close() error {
	return r.db.Close()
}

func (r *Repository) exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return r.db.ExecContext(ctx, rebindPostgres(query), args...)
}

func (r *Repository) query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, rebindPostgres(query), args...)
}

func (r *Repository) queryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return r.db.QueryRowContext(ctx, rebindPostgres(query), args...)
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	for _, stmt := range schemaStatements() {
		if _, err := r.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("postgres schema: %w", err)
		}
	}
	return nil
}

func (r *Repository) PersistScanResult(ctx context.Context, fileData map[string]interface{}, meta reportstore.ScanResultMeta) (string, error) {
	return reportstore.PersistScanResult(ctx, r.db, fileData, meta)
}

func (r *Repository) PersistPIIReport(ctx context.Context, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error {
	return reportstore.PersistPIIReport(ctx, r.db, pg, piiJSON)
}

func (r *Repository) PersistBackupComplianceReport(ctx context.Context, meta reportstore.BackupComplianceReportMeta, reportJSON map[string]interface{}) error {
	return reportstore.PersistBackupComplianceReport(ctx, r.db, meta, reportJSON)
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
	return reportstore.UpsertGucBaseline(ctx, r.db, label, settings)
}

func (r *Repository) GetGucBaseline(ctx context.Context) (string, map[string]string, string, error) {
	return reportstore.GetGucBaseline(ctx, r.db)
}

func (r *Repository) UpsertServerGucSnapshot(ctx context.Context, targetID, targetHost, nodeID string, settings map[string]string) error {
	return reportstore.UpsertServerGucSnapshot(ctx, r.db, targetID, targetHost, nodeID, settings)
}

func (r *Repository) GetServerGucSnapshot(ctx context.Context, targetID string) (map[string]string, string, string, error) {
	return reportstore.GetServerGucSnapshot(ctx, r.db, targetID)
}

func (r *Repository) ListServerGucSnapshots(ctx context.Context) ([]reportstore.GucSnapshotSummary, error) {
	return reportstore.ListServerGucSnapshots(ctx, r.db)
}

func (r *Repository) UpsertGucIgnore(ctx context.Context, scope, targetID, gucName string) error {
	return reportstore.UpsertGucIgnore(ctx, r.db, scope, targetID, gucName)
}

func (r *Repository) DeleteGucIgnore(ctx context.Context, scope, targetID, gucName string) error {
	return reportstore.DeleteGucIgnore(ctx, r.db, scope, targetID, gucName)
}

func (r *Repository) ListGucIgnores(ctx context.Context) ([]reportstore.GucIgnoreEntry, error) {
	return reportstore.ListGucIgnores(ctx, r.db)
}

func (r *Repository) UpsertGucServerGroup(ctx context.Context, id, name, description string, baseline map[string]string) (string, error) {
	return reportstore.UpsertGucServerGroup(ctx, r.db, id, name, description, baseline)
}

func (r *Repository) DeleteGucServerGroup(ctx context.Context, id string) error {
	return reportstore.DeleteGucServerGroup(ctx, r.db, id)
}

func (r *Repository) GetGucServerGroup(ctx context.Context, id string) (*reportstore.GucServerGroup, error) {
	return reportstore.GetGucServerGroup(ctx, r.db, id)
}

func (r *Repository) ListGucServerGroups(ctx context.Context) ([]reportstore.GucServerGroup, error) {
	return reportstore.ListGucServerGroups(ctx, r.db)
}

func (r *Repository) SetGucServerGroupMembers(ctx context.Context, groupID string, targetIDs []string) error {
	return reportstore.SetGucServerGroupMembers(ctx, r.db, groupID, targetIDs)
}

func (r *Repository) SetGucServerGroupBaseline(ctx context.Context, groupID string, baseline map[string]string) error {
	return reportstore.SetGucServerGroupBaseline(ctx, r.db, groupID, baseline)
}

func (r *Repository) UpsertBackupCompliancePolicy(ctx context.Context, policy reportstore.BackupCompliancePolicyStored) error {
	return reportstore.UpsertBackupCompliancePolicy(ctx, r.db, policy)
}

func (r *Repository) GetBackupCompliancePolicy(ctx context.Context) (reportstore.BackupCompliancePolicyStored, string, error) {
	return reportstore.GetBackupCompliancePolicy(ctx, r.db)
}

func (r *Repository) UpsertCollectorStatus(ctx context.Context, nodeID, hostname, ip string, ts time.Time, cronRunning bool, scheduledJobs int, lastError string) error {
	cronVal := 0
	if cronRunning {
		cronVal = 1
	}
	_, err := r.exec(ctx, `
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
}

func (r *Repository) InsertCollectorActivity(ctx context.Context, nodeID, kind, message, level string, ts time.Time) error {
	_, err := r.exec(ctx, `
		INSERT INTO collector_activity (node_id, kind, message, level, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(kind), message, strings.TrimSpace(level), ts)
	return err
}

func (r *Repository) TouchCollectorLastSeen(ctx context.Context, nodeID string, ts time.Time) error {
	_, err := r.exec(ctx, `
		UPDATE collector_status SET last_seen_at = ?, updated_at = ? WHERE node_id = ?
	`, ts, time.Now().UTC(), nodeID)
	return err
}

func (r *Repository) InsertCollectorLog(ctx context.Context, nodeID, level, message string, ts time.Time) error {
	_, err := r.exec(ctx, `
		INSERT INTO collector_logs (node_id, level, message, created_at)
		VALUES (?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(level), message, ts)
	return err
}

func (r *Repository) InsertCollectorRun(ctx context.Context, nodeID, hostname, trigger string, startedAt, finishedAt time.Time, features []string, success bool, errMsg string) error {
	featuresJSON, _ := json.Marshal(features)
	successVal := 0
	if success {
		successVal = 1
	}
	if _, err := r.exec(ctx, `
		INSERT INTO collector_runs (node_id, trigger, started_at, finished_at, features, success, error)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(trigger), startedAt, finishedAt, string(featuresJSON), successVal, strings.TrimSpace(errMsg)); err != nil {
		return err
	}
	_, err := r.exec(ctx, `
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
}

func (r *Repository) ListCollectorNodes(ctx context.Context) ([]reprows.CollectorNodeRow, error) {
	rows, err := r.query(ctx, `
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
	n, err := scanCollectorNodeRow(r.queryRow(ctx, `
		SELECT node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error
		FROM collector_status WHERE node_id = ?
	`, nodeID))
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, sql.ErrNoRows
	}
	return n, nil
}

func (r *Repository) ListCollectorRuns(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorRunRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.query(ctx, `
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
	rows, err := r.query(ctx, `
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
	rows, err := r.query(ctx, `
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

func (r *Repository) ListLogParserInactiveUsers(ctx context.Context) ([]reportstore.LogParserInactiveUserState, error) {
	return reportstore.ListLogParserInactiveUsers(ctx, r.db)
}

func (r *Repository) ListLogParserClientIPs(ctx context.Context) ([]reportstore.LogParserClientIPState, error) {
	return reportstore.ListLogParserClientIPs(ctx, r.db)
}

func (r *Repository) ListLogParserUnusedHBALines(ctx context.Context) ([]reportstore.LogParserUnusedHBAState, error) {
	return reportstore.ListLogParserUnusedHBALines(ctx, r.db)
}
