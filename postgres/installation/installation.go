package installation

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 1.2 Ensure systemd Service Files Are Enabled
func CheckSystemdServiceFiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.2",
		Title:       "Ensure systemd Service Files Are Enabled",
		Description: "Confirm, and correct if necessary, the PostgreSQL systemd service is enabled",
		Rationale:   "Enabling the systemd service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.",
		Procedure: `Run below command to see if it returns any output .
		If not then it is a FAIL.
		$ systemctl list-dependencies multi-user.target | grep -i postgres`,
		References: `CIS PostgreSQL 13 Benchmark
v1.0.0 - 02-26-2021`,
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
		Control: "1.3",
		Title:   "Ensure Data Cluster Initialized Successfully",
		Description: `First-time installs of PostgreSQL require the instantiation of the database cluster.
		A database cluster is a collection of databases that are managed by a single server instance.`,
		Procedure: `# whoami
		postgres
		# /usr/pgsql-13/bin/postgresql-13-check-db-dir ~postgres/13/data
		# echo $?
		As long as the return code is zero(0), as shown, everything is fine.`,
		Rationale: `For the purposes of security, PostgreSQL enforces ownership and permissions of the data cluster such that:
		• An initialized data cluster is owned by the UNIX account that created it.
		• The data cluster cannot be accessed by other UNIX user accounts.
		• The data-cluster cannot be created or owned by root
		• The PostgreSQL process cannot be invoked by root nor any UNIX user account other than the owner of the data cluster.
		`,
		References: `CIS PostgreSQL 13 Benchmark
v1.0.0 - 02-26-2021`,
	}
	query := `SHOW server_version;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	version := ""
	ver := 1.1
	for _, obj := range data {
		if obj["server_version"] != nil {
			version = fmt.Sprint(obj["server_version"])
			break
		}
	}
	v := strings.Split(version, " ")[0]
	if s, err := strconv.ParseFloat(v, 32); err == nil {
		ver = s
	} else {
		result.Status = "Fail"
		result.FailReason = "Unable to parse version " + version + ". Error:	" + err.Error()
		return result, nil
	}
	query = `show data_directory;`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	dataDirectory := ""
	for _, obj := range data {
		if obj["data_directory"] != nil {
			dataDirectory = fmt.Sprint(obj["data_directory"])
			break
		}
	}
	cmd := ""
	if ver >= 13 && ver < 14 {
		cmd = "sudo -u postgres /usr/pgsql-13/bin/postgresql-13-check-db-dir " + dataDirectory
	}
	if ver >= 14 && ver < 15 {
		cmd = "sudo -u postgres /usr/pgsql-14/bin/postgresql-14-check-db-dir " + dataDirectory
	}
	if ver < 13 || ver > 15 {
		result.FailReason = "The postgres version is " + version + ", which is not supported as of now."
		result.Status = "Fail"
		return result, nil
	}
	_, errStr, err := utils.ExecBash(cmd)

	if errStr != "" && err != nil {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	}

	return result, nil
}
