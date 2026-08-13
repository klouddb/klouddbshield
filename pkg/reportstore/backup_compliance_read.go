package reportstore

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// BackupComplianceRow is a stored backup compliance report for one target.
type BackupComplianceRow struct {
	ID         string
	TargetID   string
	TargetHost string
	TargetPort string
	TargetDB   string
	Report     map[string]interface{}
	ScannedAt  time.Time
}

const backupComplianceSelect = `
	id, target_id, target_host, target_port, target_db,
	backup_compliance_json, backup_compliance_scanned_at`

// GetLatestRunWithBackupCompliance returns the newest row with backup_compliance_json for target_id.
func GetLatestRunWithBackupCompliance(ctx context.Context, db *sql.DB, targetID string) (*BackupComplianceRow, error) {
	if targetID == "" {
		return nil, nil
	}
	return scanBackupComplianceRow(db.QueryRowContext(ctx, `
		SELECT `+backupComplianceSelect+`
		FROM `+RunsTable+`
		WHERE target_id = ?
		  AND backup_compliance_json IS NOT NULL
		  AND length(trim(CAST(backup_compliance_json AS TEXT))) > 2
		ORDER BY COALESCE(NULLIF(backup_compliance_scanned_at, ''), started_at) DESC, id DESC
		LIMIT 1
	`, targetID))
}

// ListBackupComplianceTargetIDs returns distinct target_ids that have backup compliance data.
func ListBackupComplianceTargetIDs(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT target_id FROM `+RunsTable+`
		WHERE backup_compliance_json IS NOT NULL
		  AND length(trim(CAST(backup_compliance_json AS TEXT))) > 2
		GROUP BY target_id
		ORDER BY max(COALESCE(NULLIF(backup_compliance_scanned_at, ''), started_at)) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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

// ListLatestBackupComplianceReports returns the latest backup compliance report per target.
func ListLatestBackupComplianceReports(ctx context.Context, db *sql.DB) ([]BackupComplianceRow, error) {
	ids, err := ListBackupComplianceTargetIDs(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make([]BackupComplianceRow, 0, len(ids))
	for _, tid := range ids {
		row, err := GetLatestRunWithBackupCompliance(ctx, db, tid)
		if err != nil {
			return nil, err
		}
		if row != nil {
			out = append(out, *row)
		}
	}
	return out, nil
}

func scanBackupComplianceRow(row *sql.Row) (*BackupComplianceRow, error) {
	var (
		id, tid, host, port, dbname string
		blob                        []byte
		scanned                     sql.NullString
	)
	if err := row.Scan(&id, &tid, &host, &port, &dbname, &blob, &scanned); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	report, err := decodeReport(blob)
	if err != nil {
		return nil, err
	}
	r := &BackupComplianceRow{
		ID: id, TargetID: tid, TargetHost: host, TargetPort: port, TargetDB: dbname, Report: report,
	}
	if scanned.Valid && scanned.String != "" {
		if t, err := time.Parse(time.RFC3339Nano, scanned.String); err == nil {
			r.ScannedAt = t
		} else if t, err := time.Parse(time.RFC3339, scanned.String); err == nil {
			r.ScannedAt = t
		}
	}
	return r, nil
}
