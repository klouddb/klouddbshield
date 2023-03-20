package replication

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 7.3 Ensure WAL archiving is configured and functional
func CheckArchiveMode(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:   "7.3",
		Rationale: `Unless the server has been correctly configured, one runs the risk of sending WALs in an unsecured, unencrypted fashion.`,
		Procedure: `Ensure archive_mode is on and have proper archive_command set`,
		References: `CIS PostgreSQL 13 Benchmark
v1.0.0 - 10-27-202`,
		Description: `Write Ahead Log (WAL) Archiving, or Log Shipping, is the process of sending transaction log files from the PRIMARY host either to one or more STANDBY hosts or to be archived on a remote storage device for later use, e.g. PITR. There are several utilities that can copy WALs including, but not limited to, cp, scp, sftp, and rynsc. 
		Basically, the server follows a set of runtime parameters which defines when the WAL should be copied using one of the aforementioned utilities.`,
		Title: "Ensure WAL archiving is configured and functional",
	}

	query := `show archive_mode;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	archiveMode := ""
	for _, obj := range data {
		if obj["archive_mode"] != nil {
			archiveMode = fmt.Sprint(obj["archive_mode"])
			break
		}
	}
	if archiveMode != "on" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}

	query = `show archive_command;`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	archiveCommand := ""
	for _, obj := range data {
		if obj["archive_command"] != nil {
			archiveCommand = fmt.Sprint(obj["archive_command"])
			break
		}
	}
	if archiveCommand == "" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}

	result.FailReason = data
	result.Status = "Pass"
	return result, nil
}
