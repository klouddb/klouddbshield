package filepermissions

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
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
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
		return result, nil
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
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
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

	cmd := "sudo ls -l " + logBinBasename + ".*" + ` | egrep  '^-[r|w]{2}-[r|w]{2}----\s*.*$' | wc -l`
	outStr, errStr, err := utils.ExecBash(cmd)
	if err != nil || errStr != "" {
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		} else {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, "", errStr)
		}
		result.Status = "Fail"
		return result, nil
	}
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		return result, nil
	}
	outStr = TrimOutput(outStr)

	var logBinCount1 int64
	if outStr != "" {
		logBinCount1, err = strconv.ParseInt(outStr, 10, 64)
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
			result.Status = "Fail"
			return result, nil
		}
	}

	cmd = "sudo ls -l " + logBinBasename + ".* | wc -l"
	outStr, errStr, err = utils.ExecBash(cmd)
	if err != nil || errStr != "" {
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		} else {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, "", errStr)
		}
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		return result, nil
	}
	outStr = TrimOutput(outStr)

	var logBinCount2 int64
	if outStr != "" {
		logBinCount2, err = strconv.ParseInt(outStr, 10, 64)
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
			result.Status = "Fail"
			return result, nil
		}
	}
	if logBinCount1 != logBinCount2 {
		result.FailReason = fmt.Sprintf("logbincont1 count %d is not equal to logbincont2 %d", logBinCount1, logBinCount2)
		result.Status = "Fail"
		return result, nil
	}
	result.Status = "Pass"
	return result, nil

	// if outStr != "" {
	// 	result.Status = "Fail"
	// 	result.FailReason = "Datadir is " + logBinBasename
	// } else {
	// 	result.Status = "Pass"
	// }
	// o.OSLevelResults = append(o.OSLevelResults, result)
	// app := "df"
	// args := []string{"-h", datadirVal}
	// outStr, _, err := Exec(app, args...)
	// log.Print(result)
	// return result, nil
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
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
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
	query := `show variables like 'slow_query_log';`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	slowQueryLogPresent := ""
	for _, obj := range data {
		if obj["Variable_name"] == "slow_query_log" {
			slowQueryLogPresent = fmt.Sprint(obj["Value"])
			break
		}
	}
	if strings.ToLower(slowQueryLogPresent) == "off" {
		result.Status = "Pass"
		// result.FailReason = "Slow query log is turned off, Please remove old slowlog files."
		return result, nil
	}

	query = `show variables like 'slow_query_log_file';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	slowQueryLog := ""
	for _, obj := range data {
		if obj["Variable_name"] == "slow_query_log_file" {
			slowQueryLog = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "sudo ls -l " + slowQueryLog + ` | egrep '^-[r|w]{2}-[r|w]{2}----\s*.*$'`
	outStr, errStr, err := utils.ExecBash(cmd)
	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	}
	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
	} else if outStr != "" {
		result.Status = "Pass"
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
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	relayLogBasename := ""
	for _, obj := range data {
		if obj["Variable_name"] == "relay_log_basename" {
			relayLogBasename = fmt.Sprint(obj["Value"])
			break
		}
	}

	cmd := "sudo ls -l " + relayLogBasename + ".* | wc -l"
	outStr, errStr, err := utils.ExecBash(cmd)
	if err != nil || errStr != "" {
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		} else {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, "", errStr)
		}
		if strings.Contains(errStr, "No such file or directory") {
			result.Status = "Pass"
			return result, nil
		}
		result.Status = "Fail"
		return result, nil
	}
	if outStr == "" && errStr == "" && err != nil && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		return result, nil
	}
	outStr = TrimOutput(outStr)

	var relayCount int64
	if outStr != "" {
		relayCount, err = strconv.ParseInt(outStr, 10, 64)
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
			result.Status = "Fail"
			return result, nil
		}
	}

	if relayCount == 0 {
		result.Status = "Pass"
		return result, nil
	}

	if relayCount > 0 {
		cmd := "sudo ls " + relayLogBasename + ".*"
		// cmd := "sudo ls -l " + logBinBasename + ".*" + ` | egrep  '^-[r|w]{2}-[r|w]{2}----\s*.*$' | wc -l`
		outStr, errStr, err := utils.ExecBash(cmd)
		if err != nil || errStr != "" {
			if err != nil {
				result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
			} else {
				result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, "", errStr)
			}
			result.Status = "Fail"
			return result, nil
		}
		if outStr == "" && errStr == "" && err != nil && strings.Contains(err.Error(), "exit status 1") {
			result.Status = "Fail"
			return result, nil
		}
		arrayofFiles := strings.Split(outStr, "\n")

		for _, file := range arrayofFiles {
			if TrimOutput(file) == "" {
				continue
			}
			cmd := "sudo ls -l " + file + ` | egrep '^-[r|w]{2}-[r|w]{2}----\s*.*$'`
			outStr, errStr, err := utils.ExecBash(cmd)
			if err != nil || errStr != "" {
				if err != nil {
					result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
				} else {
					result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, "", errStr)
				}
				result.Status = "Fail"
				return result, nil
			}
			if outStr == "" && errStr == "" && err != nil && strings.Contains(err.Error(), "exit status 1") {
				result.Status = "Fail"
				return result, nil
			}
		}

		result.Status = "Pass"
		return result, nil

	}
	return result, nil

}

// 3.6Ensure 'general_log_file' Has Appropriate Permissions
func CheckGeneralLogFilePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.6",
		Description: "Ensure 'general_log_file' Has Appropriate Permissions",
	}
	query := `select @@general_log, @@general_log_file;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	var generalLog int64
	generalLogStr := ""
	ok := false
	generalLogFile := ""
	for _, obj := range data {
		generalLogFile, ok = obj["@@general_log_file"].(string)
		if !ok {
			generalLogFile = ""
		}

		generalLog, ok = obj["@@general_log"].(int64)
		if !ok {
			generalLogStr, ok = obj["@@general_log"].(string)
			if !ok {
				generalLog = 0
			}
			if strings.ToLower(generalLogStr) == "off" {
				generalLog = 0
			} else if strings.ToLower(generalLogStr) == "on" {
				generalLog = 1
			}
			generalLog, err = strconv.ParseInt(generalLogStr, 10, 64)
			if err != nil {
				generalLog = 0
			}
		}
	}

	if generalLog == 0 {
		if utils.DoesFileExist(generalLogFile) {
			result.FailReason = fmt.Sprintf("Old general log files exist , Please remove %s", generalLogFile)
			result.Status = "Fail"
			return result, nil
		} else {
			// result.FailReason = "General log is not enabled"
			result.Status = "Pass"
			return result, nil
		}
	}
	// set global general_log=0

	cmd := "sudo ls -l " + generalLogFile + `| egrep '^-[r|w]{2}-[r|w]{2}----\s*.*$'`

	outStr, errStr, err := utils.ExecBash(cmd)

	if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if outStr == "" {
		result.Status = "Fail"
		result.FailReason = "general_log_file is " + generalLogFile + " review the permissions"
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
func IsCertType(fileName string) bool {
	certFiles := [9]string{"pem", "crt", "ca-bundle", "p7b", "p7s", "der", "cer", "pfx", "p12"}

	for _, crtType := range certFiles {
		if strings.HasSuffix(fileName, crtType) {
			return true
		}
	}
	return false
}

func TrimOutput(outStr string) string {
	outStr = strings.Trim(outStr, "\n")
	outStr = strings.Trim(outStr, " ")
	return outStr
}

// 3.7Ensure SSL Key Files Have Appropriate Permissions
func CheckSSLKeyFilePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.7",
		Description: "Ensure SSL Key Files Have Appropriate Permissions",
	}
	// query := `show variables where variable_name = 'ssl_key';`
	query := ` SELECT * FROM performance_schema.global_variables  WHERE REGEXP_LIKE(VARIABLE_NAME,'^.*ssl_(ca|capath|cert|crl|crlpath|key)$') AND VARIABLE_VALUE <> '';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))

	// certFiles = make(map[string]interface{})

	// SSLKey := ""
	certFiles := []string{}
	for _, obj := range data {
		certFiles = append(certFiles, fmt.Sprint(obj["VARIABLE_VALUE"]))
	}
	// log.Println("files are ", certFiles)

	query = `show global variables like '%datadir%';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
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

	// ls -l <ssl_file> | egrep "^-(?!r-{8}.*mysql\s*mysql).*$"

	// log.Println("data dir is", datadir)

	for _, certFile := range certFiles {
		cmd := "sudo ls -l " + datadir + certFile + " | egrep '^-r--------'"

		outStr, errStr, err := utils.ExecBash(cmd)
		if (err != nil && !strings.Contains(err.Error(), "exit status 1")) || errStr != "" {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
			result.Status = "Fail"
			return result, nil
		}
		if outStr == "" {
			result.Status = "Fail"
			result.FailReason = "cert file  " + datadir + certFile + " doesn't have correct permissions"
			return result, nil
		}
		// log.Println("outstr is empty")
	}

	for _, certFile := range certFiles {
		cmd := "sudo ls -l " + datadir + certFile + " | awk '{print $3 ,$4}'"

		outStr, errStr, err := utils.ExecBash(cmd)
		if (err != nil && !strings.Contains(err.Error(), "exit status 1")) || errStr != "" {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
			result.Status = "Fail"
			return result, nil
		}

		outStr = TrimOutput(outStr)
		if outStr != "mysql mysql" {
			result.Status = "Fail"
			result.FailReason = "cert file not present in correct group " + datadir + certFile
			return result, nil
		}
	}

	result.Status = "Pass"

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
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
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

	cmd := "sudo ls -ld " + pluginDir + " | grep \"dr-xr-x---\\|dr-xr-xr--\" | grep \"plugin\""

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
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	auditLogFile := ""
	if len(data) == 0 {
		result.Status = "Fail"
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

	if len(auditLogFile) > 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailReason = "Audit log file is empty"
	}
	return result, nil

	// cmd := "ls -l " + auditLogFile + " | egrep \"^-([rw-]{2}-){2}---[ \t]*[0-9][ \t]*mysql[\t]*mysql.*$\""
	// outStr, errStr, err := utils.ExecBash(cmd)

	// if err != nil || errStr != "" {
	// 	result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
	// 	result.Status = "Fail"
	// 	return result, nil
	// }
	// if outStr == "" {
	// 	result.Status = "Fail"
	// 	result.FailReason = "audit_log_file is " + auditLogFile
	// } else {
	// 	result.Status = "Pass"
	// }
	// return result, nil
}
