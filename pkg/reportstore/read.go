package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

const runSelectColumns = `id, started_at, finished_at, trigger, runner_name,
		target_type, target_id, target_host, target_port, target_db,
		run_status, features_run, overall_score, total_pass, total_fail, report_json,
		pii_report_json, pii_scanned_at`

// GetLatestRun returns the most recent run, optionally filtered by target_id.
func GetLatestRun(ctx context.Context, db *sql.DB, targetID string) (*RunRow, error) {
	q := `SELECT ` + runSelectColumns + ` FROM ` + RunsTable
	args := []interface{}{}
	if targetID != "" {
		q += ` WHERE target_id = ?`
		args = append(args, targetID)
	}
	q += ` ORDER BY started_at DESC,
		CASE WHEN report_json IS NOT NULL AND length(trim(CAST(report_json AS TEXT))) > 2 THEN 0 ELSE 1 END,
		finished_at DESC LIMIT 1`

	return scanRunRow(queryRowContext(ctx, db, q, args...))
}

// GetLatestRunWithPII returns the newest scan_results row that has pii_report_json for target_id.
func GetLatestRunWithPII(ctx context.Context, db *sql.DB, targetID string) (*RunRow, error) {
	if targetID == "" {
		return nil, nil
	}
	return scanRunRow(queryRowContext(ctx, db, `
		SELECT `+runSelectColumns+`
		FROM `+RunsTable+`
		WHERE target_id = ?
		  AND pii_report_json IS NOT NULL
		  AND length(trim(CAST(pii_report_json AS TEXT))) > 2
		ORDER BY COALESCE(NULLIF(pii_scanned_at, ''), started_at) DESC
		LIMIT 1
	`, targetID))
}

// GetRunByID loads a single run by id.
func GetRunByID(ctx context.Context, db *sql.DB, id string) (*RunRow, error) {
	return scanRunRow(queryRowContext(ctx, db, `
		SELECT `+runSelectColumns+`
		FROM `+RunsTable+` WHERE id = ?
	`, id))
}

// GetRuns lists recent runs newest first.
func GetRuns(ctx context.Context, db *sql.DB, limit int) ([]RunRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := queryContext(ctx, db, `
		SELECT `+runSelectColumns+`
		FROM `+RunsTable+` ORDER BY started_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RunRow
	for rows.Next() {
		r, err := scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// ListRunTargetIDs returns distinct target_id values ordered by most recent activity.
func ListRunTargetIDs(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := queryContext(ctx, db, `
		SELECT target_id FROM `+RunsTable+`
		WHERE target_id IS NOT NULL AND trim(target_id) != ''
		GROUP BY target_id
		ORDER BY max(started_at) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var tid string
		if err := rows.Scan(&tid); err != nil {
			return nil, err
		}
		if strings.TrimSpace(tid) != "" {
			out = append(out, tid)
		}
	}
	return out, rows.Err()
}

// GetRunsForTarget lists recent runs for one target, newest first.
func GetRunsForTarget(ctx context.Context, db *sql.DB, targetID string, limit int) ([]RunRow, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 15
	}
	rows, err := queryContext(ctx, db, `
		SELECT `+runSelectColumns+`
		FROM `+RunsTable+` WHERE target_id = ?
		ORDER BY started_at DESC LIMIT ?
	`, targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RunRow
	for rows.Next() {
		r, err := scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func scanRunRow(row *sql.Row) (*RunRow, error) {
	var (
		id, started, finished, trigger, runner, ttype, tid, host, port, dbname, status string
		featuresJSON                                                                   sql.NullString
		score                                                                          sql.NullFloat64
		pass, fail                                                                     sql.NullInt64
		blob                                                                           []byte
		piiBlob                                                                        []byte
		piiScanned                                                                     sql.NullString
	)
	if err := row.Scan(&id, &started, &finished, &trigger, &runner, &ttype, &tid, &host, &port, &dbname,
		&status, &featuresJSON, &score, &pass, &fail, &blob, &piiBlob, &piiScanned); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return buildRunRow(id, started, finished, trigger, runner, ttype, tid, host, port, dbname, status,
		featuresJSON, score, pass, fail, blob, piiBlob, piiScanned)
}

func scanRunFromRows(rows *sql.Rows) (*RunRow, error) {
	var (
		id, started, finished, trigger, runner, ttype, tid, host, port, dbname, status string
		featuresJSON                                                                   sql.NullString
		score                                                                          sql.NullFloat64
		pass, fail                                                                     sql.NullInt64
		blob                                                                           []byte
		piiBlob                                                                        []byte
		piiScanned                                                                     sql.NullString
	)
	if err := rows.Scan(&id, &started, &finished, &trigger, &runner, &ttype, &tid, &host, &port, &dbname,
		&status, &featuresJSON, &score, &pass, &fail, &blob, &piiBlob, &piiScanned); err != nil {
		return nil, err
	}
	return buildRunRow(id, started, finished, trigger, runner, ttype, tid, host, port, dbname, status,
		featuresJSON, score, pass, fail, blob, piiBlob, piiScanned)
}

func buildRunRow(id, started, finished, trigger, runner, ttype, tid, host, port, dbname, status string,
	featuresJSON sql.NullString, score sql.NullFloat64, pass, fail sql.NullInt64,
	blob, piiBlob []byte, piiScanned sql.NullString) (*RunRow, error) {
	st, _ := time.Parse(time.RFC3339, started)
	ft, _ := time.Parse(time.RFC3339, finished)
	report, err := decodeReport(blob)
	if err != nil {
		return nil, err
	}
	piiReport, err := decodeReport(piiBlob)
	if err != nil {
		return nil, err
	}
	var features []string
	if featuresJSON.Valid && featuresJSON.String != "" {
		_ = json.Unmarshal([]byte(featuresJSON.String), &features)
	}
	r := &RunRow{
		ID: id, StartedAt: st, FinishedAt: ft, Trigger: trigger, RunnerName: runner,
		TargetType: ttype, TargetID: tid, TargetHost: host, TargetPort: port, TargetDB: dbname,
		RunStatus: status, FeaturesRun: features, Report: report, PiiReport: piiReport,
	}
	if piiScanned.Valid && piiScanned.String != "" {
		r.PiiScannedAt, _ = time.Parse(time.RFC3339, piiScanned.String)
	}
	if score.Valid {
		r.OverallScore = score.Float64
	}
	if pass.Valid {
		r.TotalPass = int(pass.Int64)
	}
	if fail.Valid {
		r.TotalFail = int(fail.Int64)
	}
	return r, nil
}
