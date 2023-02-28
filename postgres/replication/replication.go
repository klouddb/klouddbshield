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
		Control:     "7.3",
		Description: "Ensure WAL archiving is configured and functional",
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
