package oslevelconfig

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/mysql/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// Replica checks postgresql configuration

// 1.1 Check Databases for Non-System Partitions
func IsDBOnNPS(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.1",
		Description: "Check Databases for Non-System Partitions",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables 
			  WHERE (VARIABLE_NAME LIKE '%dir' or VARIABLE_NAME LIKE '%file') 
			  and (VARIABLE_NAME NOT LIKE '%core%' AND VARIABLE_NAME <> 'local_infile' AND VARIABLE_NAME <> 'relay_log_info_file') 
			  order by VARIABLE_NAME;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	datadirVal := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "datadir" {
			datadirVal = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}

	if strings.HasPrefix(datadirVal, "/usr") || strings.HasPrefix(datadirVal, "/var") || datadirVal == "/" {
		result.Status = "Fail"
		result.FailReason = "Datadir is " + datadirVal
	} else {
		result.Status = "Pass"
	}

	// app := "df"
	// args := []string{"-h", datadirVal}
	// outStr, _, err := Exec(app, args...)
	// log.Print(outStr)
	return result, nil
}

// df -h /usr/local/mysql/data/ <datadir Value>

// 1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service
func LeastPrivileged(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.2",
		Description: "Use Dedicated Least Privileged Account for MySQL Daemon/Service",
	}
	cmd := "ps -ef | egrep \"^mysql.*$\""

	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf(cons.CMDReturnNothingFmt, cmd)
		return result, nil
	}
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}

	if outStr != "" {
		result.Status = "Pass"
	}
	return result, nil
}

// 1.3 Disable MySQL Command History
func CheckCommandHistory(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.3",
		Description: "Disable MySQL Command History ",
	}
	cmd := "find /home -name \".mysql_history\""

	outStr, errStr, err := utils.ExecBash(cmd)

	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}

	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = "Found mysql_history at " + outStr
		return result, nil
	}

	cmd = "find /root -name \".mysql_history\""

	outStr, errStr, err = utils.ExecBash(cmd)
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}
	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = " Found mysql_history at " + outStr
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}

// 1.4 Verify That the MYSQL_PWD Environment Variable is Not in Use
func CheckMYSQLPWD(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.4",
		Description: "Verify That the MYSQL_PWD Environment Variable is Not in Use",
	}
	cmd := "grep MYSQL_PWD /proc/*/environ"

	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Pass"
		return result, nil
	}

	if err != nil || errStr != "" || outStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}

	return result, nil
}

// 1.5 Ensure Interactive Login is Disabled
func CheckInteractiveLogin(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.5",
		Description: "Ensure Interactive Login is Disabled",
	}
	cmd := "getent passwd mysql | egrep \"^.*[\\/bin\\/false|\\/sbin\\/nologin]$\""

	outStr, errStr, err := utils.ExecBash(cmd)
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}

	if outStr == "" {
		result.Status = "Fail"
		result.FailReason = "Interactive Login seems enabled"
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 1.6 Verify That 'MYSQL_PWD' is Not Set in Users' Profiles
func CheckMYSQLPWDUserProfile(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.6",
		Description: "Verify That 'MYSQL_PWD' is Not Set in Users' Profiles",
	}
	cmd := "grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile}"

	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" {
		result.Status = "Pass"
		return result, nil
	}

	result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
	result.Status = "Fail"

	return result, nil
}
