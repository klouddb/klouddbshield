package installation

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 1.2 Ensure systemd Service Files Are Enabled
func CheckSystemdServiceFiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.2",
		Description: "Ensure systemd Service Files Are Enabled",
	}
	cmd := "sudo systemctl list-dependencies multi-user.target | grep -i postgres"

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr != "" {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"

	}

	return result, nil
}

// 1.3 Ensure Data Cluster Initialized Successfully
func CheckDataCluster(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.3",
		Description: "Ensure Data Cluster Initialized Successfully",
	}

	query := `show data_directory;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Skip"
		result.FailReason = data
		return result, nil
	}
	dataDirectory := ""
	for _, obj := range data {
		if obj["data_directory"] != nil {
			dataDirectory = fmt.Sprint(obj["data_directory"])
			break
		}
	}
	cmd := "sudo -u postgres postgresql-13-check-db-dir " + dataDirectory

	_, errStr, err := utils.ExecBash(cmd)

	if errStr != "" && err != nil {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"

	}

	return result, nil
}
