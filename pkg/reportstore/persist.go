package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// TargetID builds a stable id from postgres connection info.
func TargetID(pg *postgresdb.Postgres) string {
	if pg == nil {
		return "postgres:unknown"
	}
	host := NormalizeHost(pg.Host)
	port := pg.Port
	if port == "" {
		port = "5432"
	}
	db := pg.DBName
	if db == "" {
		db = "postgres"
	}
	return fmt.Sprintf("postgres:%s:%s:%s", host, port, db)
}

// GucTargetID is instance-scoped (host:port). SHOW ALL is cluster-wide, not per-database,
// so snapshots must not be keyed by dbname or the same host repeats in GUC drift.
func GucTargetID(pg *postgresdb.Postgres) string {
	if pg == nil {
		return "postgres:unknown:5432"
	}
	host := NormalizeHost(pg.Host)
	port := pg.Port
	if port == "" {
		port = "5432"
	}
	return fmt.Sprintf("postgres:%s:%s", host, port)
}

// GucInstanceKey collapses per-database target ids onto host:port for dedupe.
// Accepts "postgres:host:port:db", "postgres:host:port", or "host:port".
func GucInstanceKey(targetID string) string {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return ""
	}
	parts := strings.Split(targetID, ":")
	if len(parts) >= 3 && strings.EqualFold(parts[0], "postgres") {
		return parts[1] + ":" + parts[2]
	}
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return targetID
}

func targetFields(pg *postgresdb.Postgres) (host, port, db string) {
	if pg == nil {
		return "unknown", "5432", "postgres"
	}
	host = NormalizeHost(pg.Host)
	port = pg.Port
	if port == "" {
		port = "5432"
	}
	db = pg.DBName
	if db == "" {
		db = "postgres"
	}
	return host, port, db
}

// Persist inserts one run row with report_json stored as JSON text.
func Persist(ctx context.Context, db *sql.DB, fileData map[string]interface{}, meta RunMeta) (string, error) {
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

	featuresJSON, _ := json.Marshal(meta.FeaturesRun)
	host, port, dbName := targetFields(meta.Postgres)
	tid := TargetID(meta.Postgres)
	pass, fail, score := summarizeFromReport(fileData)

	err = execWithRetry(ctx, 30, func() error {
		return insertRunImmediate(ctx, db,
			id, started.UTC().Format(time.RFC3339), finished.UTC().Format(time.RFC3339),
			trigger, meta.RunnerName,
			"postgres", tid, host, port, dbName,
			status, string(featuresJSON), score, pass, fail, blob,
			nil, nil,
			nil, nil,
		)
	})
	if err != nil {
		return "", fmt.Errorf("insert run: %w", err)
	}
	return id, nil
}

func execInsertInTx(ctx context.Context, db *sql.DB, query string, args ...interface{}) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	return tx.Commit()
}

func insertRunImmediate(ctx context.Context, db *sql.DB, args ...interface{}) error {
	return execInsertInTx(ctx, db, `
		INSERT INTO `+RunsTable+` (
			id, started_at, finished_at, trigger, runner_name,
			target_type, target_id, target_host, target_port, target_db,
			run_status, features_run, overall_score, total_pass, total_fail, report_json,
			pii_report_json, pii_scanned_at,
			backup_compliance_json, backup_compliance_scanned_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, args...)
}

func execWithRetry(ctx context.Context, attempts int, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !IsSQLiteBusy(err) || i == attempts-1 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(250*(i+1)) * time.Millisecond):
		}
	}
	return err
}

// IsSQLiteBusy reports lock contention on klouddbshield.db (collector, DB Browser, etc.).
func IsSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "sqlite_busy")
}

func summarizeFromReport(fileData map[string]interface{}) (pass, fail int, score float64) {
	pr, ok := fileData["Postgres Report"].(map[string]interface{})
	if !ok {
		return 0, 0, 0
	}
	if sc, ok := pr["score"].(map[string]interface{}); ok {
		if v, ok := sc["Pass"].(float64); ok {
			pass = int(v)
		} else if v, ok := sc["Pass"].(int); ok {
			pass = v
		}
		if v, ok := sc["Fail"].(float64); ok {
			fail = int(v)
		} else if v, ok := sc["Fail"].(int); ok {
			fail = v
		}
	}
	if pass+fail == 0 {
		pass, fail = countPassFailFromResult(pr["result"])
	}
	total := pass + fail
	if total > 0 {
		score = float64(pass) / float64(total) * 100
	}
	return pass, fail, score
}

// countPassFailFromResult tallies CIS controls from Postgres Report.result[].
func countPassFailFromResult(raw interface{}) (pass, fail int) {
	if raw == nil {
		return 0, 0
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return 0, 0
	}
	var rows []struct {
		Status string `json:"Status"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return 0, 0
	}
	for _, r := range rows {
		if strings.EqualFold(r.Status, "Pass") {
			pass++
		} else if strings.EqualFold(r.Status, "Fail") {
			fail++
		}
	}
	return pass, fail
}
