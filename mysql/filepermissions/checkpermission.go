package filepermissions

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/mysql/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 3.1 Ensure 'datadir' Has Appropriate Permissions
func CheckDataDirPerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables
	WHERE VARIABLE_NAME LIKE 'datadir';`
	result := &model.Result{
		Control:     "3.1",
		Description: "Ensure 'datadir' Has Appropriate Permissions",
	}
	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	datadirVal := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "datadir" {
			datadirVal = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}
	cmd := "ls -ld " + datadirVal + " | grep \"drwxr-x---.*mysql.*mysql\""
	// log.Print(cmd)
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

	if outStr == "" {
		result.Status = "Fail"
		result.FailReason = "Datadir is " + datadirVal
	} else {
		result.Status = "Pass"
	}
	// o.OSLevelResults = append(o.OSLevelResults, result)
	// app := "df"
	// args := []string{"-h", datadirVal}
	// outStr, _, err := Exec(app, args...)
	// log.Print(result)
	return result, nil
}

// 3.2Ensure 'log_bin_basename' Files Have Appropriate Permissions
func CheckLogBinBasenamePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.2",
		Description: "Ensure 'log_bin_basename' Files Have Appropriate Permissions",
	}
	query := `show variables like 'log_bin_basename';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	logBinBasename := ""
	for _, obj := range data {
		if obj["Variable_name"] == "log_bin_basename" {
			logBinBasename = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "ls -l | egrep '^-(?![r|w]{2}-[r|w]{2}----.*mysql\\s*mysql).*" + logBinBasename + ".*$'"
	// log.Print(cmd)
	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Pass"
		return result, nil
	}
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}

	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = "Datadir is " + logBinBasename
	} else {
		result.Status = "Pass"
	}
	// o.OSLevelResults = append(o.OSLevelResults, result)
	// app := "df"
	// args := []string{"-h", datadirVal}
	// outStr, _, err := Exec(app, args...)
	// log.Print(result)
	return result, nil
}

// 3.3Ensure 'log_error' Has Appropriate Permissions
func CheckLogErrorPerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.3",
		Description: "Ensure 'log_error' Has Appropriate Permissions",
	}
	query := `show variables like 'log_error';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	logerror := ""
	for _, obj := range data {
		if obj["Variable_name"] == "log_error" {
			logerror = fmt.Sprint(obj["Value"])
			break
		}
	}
	cmd := "sudo ls -l " + logerror + " | grep '^-rw-------.*mysql.*mysql.*$'"
	// log.Print(cmd)
	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf(cons.ExpectedOutput, cmd)
		return result, nil
	} else if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	}
	if outStr != "" {
		result.Status = "Pass"
	}
	// o.OSLevelResults = append(o.OSLevelResults, result)
	// app := "df"
	// args := []string{"-h", datadirVal}
	// outStr, _, err := Exec(app, args...)
	// log.Print(result)
	return result, nil
}

// 3.4Ensure 'slow_query_log' Has Appropriate Permissions
func CheckSlowQueryLogPerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.4",
		Description: "Ensure 'slow_query_log' Has Appropriate Permissions",
	}
	query := `show variables like 'slow_query_log_file';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	slowQueryLog := ""
	for _, obj := range data {
		if obj["Variable_name"] == "slow_query_log_file" {
			slowQueryLog = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "ls -l | egrep \"^-(?![r|w]{2}-[r|w]{2}----.*mysql\\s*mysql).*" + slowQueryLog + ".*$\""
	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Pass"
	} else if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	}
	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = "Datadir is " + slowQueryLog
	}
	return result, nil
}

// 3.5Ensure 'relay_log_basename' Files Have Appropriate Permissions
func CheckRelayLogBasenamePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.5",
		Description: "Ensure 'relay_log_basename' Files Have Appropriate Permissions",
	}
	query := `show variables like 'relay_log_basename';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	relayLogBasename := ""
	for _, obj := range data {
		if obj["Variable_name"] == "relay_log_basename" {
			relayLogBasename = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "ls -l | egrep \"^-(?![r|w]{2}-[r|w]{2}----.*mysql\\s*mysql).*" + relayLogBasename + ".*$\""

	outStr, errStr, err := utils.ExecBash(cmd)
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Pass"
		return result, nil
	}
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, err
	}

	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = "Datadir is " + relayLogBasename
	} else {
		result.Status = "Pass"
	}

	return result, nil
}

// 3.6Ensure 'general_log_file' Has Appropriate Permissions
func CheckGeneralLogFilePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.6",
		Description: "Ensure 'general_log_file' Has Appropriate Permissions",
	}
	query := `show variables like 'general_log_file';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	generalLogFile := ""
	for _, obj := range data {
		if obj["Variable_name"] == "general_log_file" {
			generalLogFile = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "sudo ls -l " + generalLogFile + " grep '^-rw-------.*mysql.*mysql'"

	outStr, errStr, err := utils.ExecBash(cmd)

	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = "general_log_file is " + generalLogFile + " with output " + outStr
	} else {
		result.Status = "Pass"
	}
	// o.OSLevelResults = append(o.OSLevelResults, result)
	// app := "df"
	// args := []string{"-h", datadirVal}
	// outStr, _, err := Exec(app, args...)
	// log.Print(result)
	return result, nil
}

// 3.7Ensure SSL Key Files Have Appropriate Permissions
func CheckSSLKeyFilePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.7",
		Description: "Ensure SSL Key Files Have Appropriate Permissions",
	}
	query := `show variables where variable_name = 'ssl_key';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	SSLKey := ""
	for _, obj := range data {
		if obj["Variable_name"] == "ssl_key" {
			SSLKey = fmt.Sprint(obj["Value"])
			break
		}
	}
	query = `show global variables like '%datadir%';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	datadir := ""
	for _, obj := range data {
		if obj["Variable_name"] == "datadir" {
			datadir = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "sudo ls -l " + datadir + SSLKey + " | egrep '^-r--------[ \t]*.[ \t]*mysql[ \t]*mysql.*$'"

	outStr, errStr, err := utils.ExecBash(cmd)

	if (err != nil && !strings.Contains(err.Error(), "exit status 1")) || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if outStr != "" {
		result.Status = "Fail"
		result.FailReason = "ssl_key is " + SSLKey
	} else {
		result.Status = "Pass"
	}
	// log.Print(result)
	return result, nil
}

// 3.8Ensure Plugin Directory Has Appropriate Permissions
func CheckPluginDirPerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.8",
		Description: "Ensure Plugin Directory Has Appropriate Permissions",
	}
	query := `show variables where variable_name = 'plugin_dir';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	pluginDir := ""
	for _, obj := range data {
		if obj["Variable_name"] == "plugin_dir" {
			pluginDir = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "ls -l " + pluginDir + " | grep \"dr-xr-x---\\|dr-xr-xr--\" | grep \"plugin\""

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf(cons.ExpectedOutput, cmd)
		return result, nil
	}
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	} else if outStr != "" {
		result.Status = "Pass"
	}
	// log.Print(result)
	return result, nil
}

// 3.9Ensure 'audit_log_file' Has Appropriate Permissions
func CheckAuditLogFilePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.9",
		Description: "Ensure 'audit_log_file' Has Appropriate Permissions",
	}
	query := `show global variables where variable_name='audit_log_file';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return result, err
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	auditLogFile := ""
	if len(data) == 0 {
		result.Status = "bypass"
		result.FailReason = "Unable to fetch audit_log_file from mysql database"
		// log.Print(result)
		return result, nil
	}
	for _, obj := range data {
		if obj["Variable_name"] == "audit_log_file" {
			auditLogFile = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "ls -l " + auditLogFile + " | egrep \"^-([rw-]{2}-){2}---[ \t]*[0-9][ \t]*mysql[\t]*mysql.*$\""
	outStr, errStr, err := utils.ExecBash(cmd)

	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if outStr == "" {
		result.Status = "Fail"
		result.FailReason = "audit_log_file is " + auditLogFile
	} else {
		result.Status = "Pass"
	}
	return result, nil
}
