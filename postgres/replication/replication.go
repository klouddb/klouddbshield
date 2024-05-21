package replication

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

// 7.4 Ensure WAL archiving is configured and functional
func CheckArchiveMode(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:   "7.4",
		Rationale: `Unless the server has been correctly configured, one runs the risk of sending WALs in an unsecured, unencrypted fashion.`,
		Procedure: `Ensure archive_mode is on and have proper archive_command or archive_library set`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
		Description: `Write Ahead Log (WAL) Archiving, or Log Shipping, is the process of sending transaction log files from the PRIMARY host 
		either to one or more STANDBY hosts or to be archived on a remote storage device for later use, e.g. PITR. 
		There are several utilities that can copy WALs including, but not limited to, cp, scp, sftp, and rynsc. 
		Basically, the server follows a set of runtime parameters which defines when the WAL should be copied using one of the aforementioned utilities.`,
		Title: "Ensure WAL archiving is configured and functional",
	}
	// Query to check the WAL archiving settings
	query := `
SELECT name, setting
FROM pg_settings
WHERE name IN ('archive_mode', 'archive_command', 'archive_library')
AND setting IS NOT NULL
AND setting <> 'off'
AND setting <> '(disabled)'
AND setting <> '';`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf("Error executing query: %v", err)
		return result, nil
	}
	defer rows.Close()

	// Check if the necessary settings are enabled
	archivingEnabled := false
	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Error scanning row: %v", err)
			return result, nil
		}
		if (name == "archive_mode" && setting == "on") || (name == "archive_command" && setting != "") || (name == "archive_library" && setting != "") {
			archivingEnabled = true
		}
	}

	if !archivingEnabled {
		result.Status = "Fail"
		result.FailReason = "WAL archiving is not properly configured, archive_mode is off or archive_command/archive_library is not set"
		return result, nil
	}

	// // To verify WAL archiving is functioning successfully:
	// statsQuery := "SELECT archived_count, last_archived_wal, last_archived_time, failed_count FROM pg_stat_archiver;"
	// var archivedCount int
	// var lastArchivedWal, lastArchivedTime string
	// var failedCount int

	// err = db.QueryRowContext(ctx, statsQuery).Scan(&archivedCount, &lastArchivedWal, &lastArchivedTime, &failedCount)
	// if err != nil {
	// 	result.Status = "Fail"
	// 	result.FailReason = fmt.Sprintf("Error fetching WAL archiving stats: %v", err)
	// 	return result, nil
	// }

	// if failedCount > 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = fmt.Sprintf("WAL archiving errors detected: %d failures", failedCount)
	// 	return result, nil
	// }

	result.Status = "Pass"
	return result, nil
}
