package replication

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"

	"github.com/klouddb/klouddbshield/postgres/helper"
)

// 7.4 Ensure WAL archiving is configured and functional
func CheckArchiveMode() helper.CheckHelper {
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

	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {
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
	})
}

func CheckReplicationUser() helper.CheckHelper {
	result := &model.Result{
		Control: "7.1",
		Title:   "Ensure a replication-only user is created and used for streaming replication",
		Description: `Create a new user specifically for use by streaming replication instead of using the
		superuser account.`,
		Rationale: `As it is not necessary to be a superuser to initiate a replication connection, it is proper to
		create an account specifically for replication. This allows further 'locking down' the uses
		of the superuser account and follows the general principle of using the least privileges
		necessary.`,
		Procedure: "select rolname from pg_roles where rolreplication is true;",
		Status:    "Manual",
	}

	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {
		query := `select rolname from pg_roles where rolreplication is true;`

		roleNames, err := utils.GetListFromQuery(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Error executing query: %v", err)
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Please make sure you use separate user for replication (Least privilege rule applies ). Check below output and take necessary action`,
			List:        roleNames,
		}

		return result, nil
	})
}

func CheckReplicationLogging() helper.CheckHelper {
	result := &model.Result{
		Control: "7.2",
		Title:   "Ensure logging of replication commands is configured",
		Description: `Enabling the log_replication_commands setting causes each attempted replication from
		the server to be logged.`,
		Rationale: `A successful replication connection allows for a complete copy of the data stored within
		the data cluster to be offloaded to another, potentially insecure, host.`,
		Procedure: "show log_replication_commands;",
		Status:    "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		query := `show log_replication_commands;`

		out, err := utils.GetListFromQuery(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Error executing query: %v", err)
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Please log replication commands if you are using replication. Check below output and take necessary action`,
			List:        out,
		}

		return result, nil
	})
}

func CheckBaseBackupConfiguration() helper.CheckHelper {
	result := &model.Result{
		Control: "7.3",
		Title:   "Ensure base backups are configured and functional",
		Description: `The PostgreSQL CLI pg_basebackup can be used, however, TLS
		encryption should be enabled on the server as per section 6.8 of this benchmark. The
		pgBackRest tool detailed in section 8.2 of this benchmark can also be used to create a
		'base backup'.`,
		Rationale: `TLS encryption should be enabled on the server as per section 6.8 of
		this benchmark.Backups should be secured properly`,
		Procedure: "pg_basebackup --version",
		Status:    "Manual",
	}
	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {

		cmd := `pg_basebackup --version`

		outStr, errStr, err := utils.ExecBash(cmd)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Please ensure that pg_basebackup is properly setup meeting your Org security standards

		Check below output and take necessary action`,
			List: strings.Split(outStr, "\n"),
		}

		return result, nil
	})
}

func CheckStreamingReplicationConfiguration() helper.CheckHelper {
	result := &model.Result{
		Control: "7.5",
		Title:   "Ensure streaming replication parameters are configured correctly",
		Description: `Streaming replication from a PRIMARY host transmits DDL, DML, passwords, and other
		potentially sensitive activities and data. These connections should be protected with
		Secure Sockets Layer (SSL).`,
		Rationale: `Unencrypted transmissions could reveal sensitive information to unauthorized parties.
		Unauthenticated connections could enable man-in-the-middle attacks.`,
		Procedure: `show primary_conninfo ;
		select rolname from pg_roles where rolreplication is true;`,
		Status: "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		query := `show primary_conninfo;`
		list, err := utils.GetListFromQuery(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		query = `select rolname from pg_roles where rolreplication is true;`
		data, err := utils.GetTableResponse(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Confirm a dedicated and non-superuser role with replication permission exists;
		Please make sure your primary_conninfo looks accurate.
	 	e.g "primary_conninfo = 'user=replication_user password=mypassword host=mySrcHost
port=5432 sslmode=require sslcompression=1'"`,
			List:  list,
			Table: data,
		}

		return result, nil
	})
}
