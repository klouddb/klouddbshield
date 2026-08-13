package backupcompliance

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// RawBackup is one row from the pg_backup_compliance extension view.
// Columns match https://github.com/klouddb/pg_backup_compliance
type RawBackup struct {
	BackendPID      int
	BackendStart    time.Time
	ApplicationName string
	BackupType      string
	DatabaseName    string
	UserName        string
	ClientAddr      string
	IsWalSender     bool
	StartTime       time.Time
	EndTime         time.Time
	Status          string
	ExitCode        sql.NullInt64
	ErrorMessage    string
	ConnectionCount int
}

// QueryBackups loads all rows from the pg_backup_compliance extension view.
func QueryBackups(ctx context.Context, db *sql.DB) ([]RawBackup, error) {
	// Full column set from the extension (client_addr is text in the SQL surface).
	const q = `
SELECT
	COALESCE(backend_pid, 0),
	backend_start,
	COALESCE(application_name, ''),
	COALESCE(backup_type, ''),
	COALESCE(database_name, ''),
	COALESCE(user_name, ''),
	COALESCE(client_addr, ''),
	COALESCE(is_walsender, false),
	start_time,
	end_time,
	COALESCE(status, ''),
	exit_code,
	COALESCE(error_message, ''),
	COALESCE(connection_count, 0)
FROM pg_backup_compliance
ORDER BY start_time DESC`

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		if isMissingRelation(err) {
			return nil, fmt.Errorf("pg_backup_compliance extension not installed or relation missing: %w", err)
		}
		return nil, fmt.Errorf("query pg_backup_compliance: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []RawBackup
	for rows.Next() {
		var b RawBackup
		var backendStart, start, end sql.NullTime
		if err := rows.Scan(
			&b.BackendPID,
			&backendStart,
			&b.ApplicationName,
			&b.BackupType,
			&b.DatabaseName,
			&b.UserName,
			&b.ClientAddr,
			&b.IsWalSender,
			&start,
			&end,
			&b.Status,
			&b.ExitCode,
			&b.ErrorMessage,
			&b.ConnectionCount,
		); err != nil {
			return nil, fmt.Errorf("scan pg_backup_compliance row: %w", err)
		}
		if backendStart.Valid {
			b.BackendStart = backendStart.Time
		}
		if start.Valid {
			b.StartTime = start.Time
		}
		if end.Valid {
			b.EndTime = end.Time
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func isMissingRelation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "undefined_table") ||
		strings.Contains(msg, "relation") && strings.Contains(msg, "pg_backup_compliance")
}
