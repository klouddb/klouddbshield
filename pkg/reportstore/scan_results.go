package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// ScanResultMeta extends run metadata with collector node attribution.
type ScanResultMeta struct {
	RunMeta
	NodeID       string
	Hostname     string
	ErrorMessage string
}

// PersistScanResult inserts into scan_results (uses RunsTable when set to scan_results).
func PersistScanResult(ctx context.Context, db *sql.DB, fileData map[string]interface{}, meta ScanResultMeta) (string, error) {
	if RunsTable != "scan_results" {
		id, err := Persist(ctx, db, fileData, meta.RunMeta)
		return id, err
	}
	if fileData == nil {
		fileData = map[string]interface{}{}
	}
	blob, err := encodeReport(fileData)
	if err != nil {
		return "", err
	}

	id := uuid.NewString()
	started := meta.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	finished := meta.FinishedAt
	if finished.IsZero() {
		finished = time.Now().UTC()
	}
	trigger := meta.Trigger
	if trigger == "" {
		trigger = "cron"
	}
	status := meta.RunStatus
	if status == "" {
		status = "success"
	}
	if meta.ErrorMessage != "" {
		status = "failed"
	}

	featuresJSON, _ := json.Marshal(meta.FeaturesRun)
	host, port, dbName := targetFields(meta.Postgres)
	tid := TargetID(meta.Postgres)
	pass, fail, score := summarizeFromReport(fileData)

	err = execWithRetry(ctx, 30, func() error {
		return insertScanResultImmediate(ctx, db,
			id, meta.NodeID, meta.Hostname,
			started.UTC().Format(time.RFC3339), finished.UTC().Format(time.RFC3339),
			trigger, meta.RunnerName,
			"postgres", tid, host, port, dbName,
			status, string(featuresJSON), score, pass, fail, blob,
			nil, nil,
			nil, nil,
			meta.ErrorMessage,
		)
	})
	if err != nil {
		return "", fmt.Errorf("insert scan_result: %w", err)
	}
	return id, nil
}

func insertScanResultImmediate(ctx context.Context, db *sql.DB, args ...interface{}) error {
	return execInsertInTx(ctx, db, `
		INSERT INTO scan_results (
			id, node_id, hostname, started_at, finished_at, trigger, runner_name,
			target_type, target_id, target_host, target_port, target_db,
			run_status, features_run, overall_score, total_pass, total_fail, report_json,
			pii_report_json, pii_scanned_at,
			backup_compliance_json, backup_compliance_scanned_at, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, args...)
}

// EnsureScanResultsSchema creates scan_results and GUC tables on main-server DB.
func EnsureScanResultsSchema(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS scan_results (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			hostname TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			trigger TEXT NOT NULL DEFAULT 'cron',
			runner_name TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL DEFAULT 'postgres',
			target_id TEXT NOT NULL,
			target_host TEXT NOT NULL,
			target_port TEXT NOT NULL DEFAULT '',
			target_db TEXT NOT NULL DEFAULT '',
			run_status TEXT NOT NULL,
			features_run TEXT,
			overall_score REAL,
			total_pass INTEGER DEFAULT 0,
			total_fail INTEGER DEFAULT 0,
			report_json JSON NOT NULL,
			pii_report_json JSON,
			pii_scanned_at TEXT,
			backup_compliance_json JSON,
			backup_compliance_scanned_at TEXT,
			error_message TEXT
		)`,
		// ALTERs for older DBs; ignore duplicate column.
		`ALTER TABLE scan_results ADD COLUMN pii_report_json JSON`,
		`ALTER TABLE scan_results ADD COLUMN pii_scanned_at TEXT`,
		`ALTER TABLE scan_results ADD COLUMN backup_compliance_json JSON`,
		`ALTER TABLE scan_results ADD COLUMN backup_compliance_scanned_at TEXT`,
		`ALTER TABLE scan_results ADD COLUMN error_message TEXT`,
		`CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_results_node ON scan_results(node_id, started_at DESC)`,
		`CREATE TABLE IF NOT EXISTS guc_baseline (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL DEFAULT 'global',
			settings_json JSON NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS server_guc_snapshots (
			target_id TEXT PRIMARY KEY,
			target_host TEXT NOT NULL,
			node_id TEXT NOT NULL,
			settings_json JSON NOT NULL,
			collected_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS guc_drift_ignores (
			id TEXT PRIMARY KEY,
			scope TEXT NOT NULL,
			target_id TEXT NOT NULL,
			instance_key TEXT NOT NULL,
			guc_name TEXT NOT NULL DEFAULT '',
			ignored_at TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_guc_drift_ignores_unique
			ON guc_drift_ignores(scope, instance_key, guc_name)`,
		`CREATE TABLE IF NOT EXISTS guc_server_groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			baseline_json JSON NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS guc_server_group_members (
			group_id TEXT NOT NULL,
			target_id TEXT NOT NULL,
			PRIMARY KEY (group_id, target_id)
		)`,
		`CREATE TABLE IF NOT EXISTS backup_compliance_policy (
			id TEXT PRIMARY KEY,
			policy_json JSON NOT NULL,
			updated_at TEXT NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			if isIgnorableMigrationErr(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// PostgresFromTarget builds postgres config from scan target fields.
func PostgresFromTarget(host, port, dbName string) *postgresdb.Postgres {
	return &postgresdb.Postgres{
		Host:   NormalizeHost(host),
		Port:   port,
		DBName: dbName,
	}
}
