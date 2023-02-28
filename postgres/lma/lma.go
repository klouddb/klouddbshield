package lma

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 3.1 Ensure the log destinations are set correctly
func CheckLogDest(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1",
		Description: "Ensure the log destinations are set correctly",
	}

	query := `show log_destination;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) >= 0 {
	// 	result.Status = "Pass"
	// 	result.FailReason = data
	// 	return result, nil
	// }
	logDestination := ""
	for _, obj := range data {
		if obj["log_destination"] != nil {
			logDestination = fmt.Sprint(obj["log_destination"])
			break
		}
	}
	if logDestination == "stderr" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil

	// cmd := "sudo -u postgres postgresql-13-check-db-dir " + dataDirectory

	// _, errStr, err := utils.ExecBash(cmd)

	// if errStr != "" && err != nil {
	// 	result.Status = "Pass"
	// } else {
	// 	result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
	// 	result.Status = "Fail"

	// }

}

// 3.1.3 Ensure the logging collector is enabled
func CheckLogCol(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.3",
		Description: "Ensure the logging collector is enabled",
	}

	query := `show logging_collector;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	loggingCollector := ""
	for _, obj := range data {
		if obj["logging_collector"] != nil {
			loggingCollector = fmt.Sprint(obj["logging_collector"])
			break
		}
	}
	if loggingCollector != "on" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.4 Ensure the log file destination directory is set correctly
func CheckLogDir(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.4",
		Description: "Ensure the log file destination directory is set correctly",
	}

	query := `show log_directory;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logDirectory := ""
	for _, obj := range data {
		if obj["log_directory"] != nil {
			logDirectory = fmt.Sprint(obj["log_directory"])
			break
		}
	}
	if logDirectory == "" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.5 Ensure the filename pattern for log files is set correctly
func CheckLogFile(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.5",
		Description: "Ensure the filename pattern for log files is set correctly",
	}

	query := `show log_filename;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logFilename := ""
	for _, obj := range data {
		if obj["log_filename"] != nil {
			logFilename = fmt.Sprint(obj["log_filename"])
			break
		}
	}
	if logFilename == "" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.6 Ensure the log file permissions are set correctly
func CheckLogFilePerm(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.6",
		Description: "Ensure the log file permissions are set correctly",
	}

	query := `show log_file_mode;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logFileMode := ""
	for _, obj := range data {
		if obj["log_file_mode"] != nil {
			logFileMode = fmt.Sprint(obj["log_file_mode"])
			break
		}
	}
	if logFileMode != "0600" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.7 Ensure 'log_truncate_on_rotation' is enabled
func CheckLogTrunc(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.7",
		Description: "Ensure 'log_truncate_on_rotation' is enabled",
	}

	query := `show log_truncate_on_rotation;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logTruncateOnRotation := ""
	for _, obj := range data {
		if obj["log_truncate_on_rotation"] != nil {
			logTruncateOnRotation = fmt.Sprint(obj["log_truncate_on_rotation"])
			break
		}
	}
	if logTruncateOnRotation != "on" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.8 Ensure the maximum log file lifetime is set correctly
func CheckLogLT(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.8",
		Description: "Ensure the maximum log file lifetime is set correctly",
	}

	query := `show log_rotation_age;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logRotationAge := ""
	for _, obj := range data {
		if obj["log_rotation_age"] != nil {
			logRotationAge = fmt.Sprint(obj["log_rotation_age"])
			break
		}
	}
	if logRotationAge == "1d" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.9 Ensure the maximum log file size is set correctly
func CheckLogFileSize(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.9",
		Description: "Ensure the maximum log file size is set correctly",
	}

	query := `show log_rotation_size;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logRotationSize := ""
	for _, obj := range data {
		if obj["log_rotation_size"] != nil {
			logRotationSize = fmt.Sprint(obj["log_rotation_size"])
			break
		}
	}
	if logRotationSize == "0" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.10 Ensure the correct syslog facility is selected
func CheckSyslog(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.10",
		Description: "Ensure the correct syslog facility is selected",
	}

	query := `show syslog_facility;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	syslogFacility := ""
	for _, obj := range data {
		if obj["syslog_facility"] != nil {
			syslogFacility = fmt.Sprint(obj["syslog_facility"])
			break
		}
	}
	if !strings.Contains(syslogFacility, "local") {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.11 Ensure the program name for PostgreSQL syslog messages is correct
func CheckSyslogMsg(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.11",
		Description: "Ensure the program name for PostgreSQL syslog messages is correct",
	}

	query := `show syslog_ident;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	syslogIdent := ""
	for _, obj := range data {
		if obj["syslog_ident"] != nil {
			syslogIdent = fmt.Sprint(obj["syslog_ident"])
			break
		}
	}
	if syslogIdent == "" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.12 Ensure the correct messages are written to the server log
func CheckServLogMsg(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.12",
		Description: "Ensure the correct messages are written to the server log",
	}

	query := `show log_min_messages;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logMinMessages := ""
	for _, obj := range data {
		if obj["log_min_messages"] != nil {
			logMinMessages = fmt.Sprint(obj["log_min_messages"])
			break
		}
	}
	if logMinMessages != "warning" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.13 Ensure the correct SQL statements generating errors are recorded
func CheckSQLStat(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.13",
		Description: "Ensure the correct SQL statements generating errors are recorded",
	}

	query := `show log_min_error_statement ;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	statementinMessages := ""
	for _, obj := range data {
		if obj["log_min_error_statement"] != nil {
			statementinMessages = fmt.Sprint(obj["log_min_error_statement"])
			break
		}
	}
	if statementinMessages != "error" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.14 Ensure 'debug_print_parse' is disabled
func CheckDebugPrintParse(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.14",
		Description: "Ensure 'debug_print_parse' is disabled",
	}

	query := `show debug_print_parse;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	debugPrintParse := ""
	for _, obj := range data {
		if obj["debug_print_parse"] != nil {
			debugPrintParse = fmt.Sprint(obj["debug_print_parse"])
			break
		}
	}
	if debugPrintParse != "off" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.15 Ensure 'debug_print_rewritten' is disabled
func CheckDebugPrintRewritten(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.15",
		Description: "Ensure 'debug_print_rewritten' is disabled",
	}

	query := `show debug_print_rewritten;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	debugPrintRewritten := ""
	for _, obj := range data {
		if obj["debug_print_rewritten"] != nil {
			debugPrintRewritten = fmt.Sprint(obj["debug_print_rewritten"])
			break
		}
	}
	if debugPrintRewritten != "off" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.16 Ensure 'debug_print_plan' is disabled
func CheckDebugPrintPlan(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.16",
		Description: "Ensure 'debug_print_plan' is disabled",
	}

	query := `show debug_print_plan;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	debugPrintPlan := ""
	for _, obj := range data {
		if obj["debug_print_plan"] != nil {
			debugPrintPlan = fmt.Sprint(obj["debug_print_plan"])
			break
		}
	}
	if debugPrintPlan != "off" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.17 Ensure 'debug_pretty_print' is enabled
func CheckDebugPrettyPrint(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.17",
		Description: "Ensure 'debug_pretty_print' is enabled",
	}

	query := `show debug_pretty_print;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	debugPrettyPrint := ""
	for _, obj := range data {
		if obj["debug_pretty_print"] != nil {
			debugPrettyPrint = fmt.Sprint(obj["debug_pretty_print"])
			break
		}
	}
	if debugPrettyPrint != "on" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.18 Ensure 'log_connections' is enabled
func CheckLogConnections(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.18",
		Description: "Ensure 'log_connections' is enabled",
	}

	query := `show log_connections;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logConnections := ""
	for _, obj := range data {
		if obj["log_connections"] != nil {
			logConnections = fmt.Sprint(obj["log_connections"])
			break
		}
	}
	if logConnections != "on" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.19 Ensure 'log_disconnections' is enabled
func CheckLogDisconnections(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.19",
		Description: "Ensure 'log_disconnections' is enabled",
	}

	query := `show log_disconnections;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logDisconnections := ""
	for _, obj := range data {
		if obj["log_disconnections"] != nil {
			logDisconnections = fmt.Sprint(obj["log_disconnections"])
			break
		}
	}
	if logDisconnections != "on" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.20 Ensure 'log_error_verbosity' is set correctly
func ChecklogErrorVerbosity(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.20",
		Description: "Ensure 'log_error_verbosity' is set correctly",
	}

	query := `show log_error_verbosity ;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logErrorVerbosity := ""
	for _, obj := range data {
		if obj["log_error_verbosity"] != nil {
			logErrorVerbosity = fmt.Sprint(obj["log_error_verbosity"])
			break
		}
	}
	if logErrorVerbosity != "verbose" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.21 Ensure 'log_hostname' is set correctly
func CheckLogHostname(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.21",
		Description: "Ensure 'log_hostname' is set correctly",
	}

	query := `show log_hostname;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logHostname := ""
	for _, obj := range data {
		if obj["log_hostname"] != nil {
			logHostname = fmt.Sprint(obj["log_hostname"])
			break
		}
	}
	if logHostname != "off" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.22 Ensure 'log_line_prefix' is set correctly
func ChecklogLinePrefix(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.22",
		Description: "Ensure 'log_line_prefix' is set correctly",
	}

	query := `show log_line_prefix;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logLinePrefix := ""
	for _, obj := range data {
		if obj["log_line_prefix"] != nil {
			logLinePrefix = fmt.Sprint(obj["log_line_prefix"])
			break
		}
	}
	if logLinePrefix != "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.23 Ensure 'log_statement' is set correctly
func CheckLogStatement(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.23",
		Description: "Ensure 'log_statement' is set correctly",
	}

	query := `show log_statement;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logStatement := ""
	for _, obj := range data {
		if obj["log_statement"] != nil {
			logStatement = fmt.Sprint(obj["log_statement"])
			break
		}
	}
	if logStatement == "none" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.1.24 Ensure 'log_timezone' is set correctly
func CheckLogTimezone(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.1.24",
		Description: "Ensure 'log_timezone' is set correctly",
	}

	query := `show log_timezone;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	logTimezone := ""
	for _, obj := range data {
		if obj["log_timezone"] != nil {
			logTimezone = fmt.Sprint(obj["log_timezone"])
			break
		}
	}
	if logTimezone != "GMT" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled
func CheckSharedPreloadLibraries(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "3.2",
		Description: "Ensure the PostgreSQL Audit Extension (pgAudit) is enabled",
	}

	query := `show shared_preload_libraries ;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	sharedPreloadLibraries := ""
	for _, obj := range data {
		if obj["shared_preload_libraries"] != nil {
			sharedPreloadLibraries = fmt.Sprint(obj["shared_preload_libraries"])
			break
		}
	}
	if !strings.Contains(sharedPreloadLibraries, "pgaudit") {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}
