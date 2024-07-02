package auditinglogging

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 6.1 Ensure 'log_error' is configured correctly
func CheckLogError(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.1",
		Description: "Ensure 'log_error' is configured correctly",
	}
	query := `SHOW variables LIKE 'log_error';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	// if len(data) == 0 {
	// 	result.Status = "Pass"
	// 	log.Print(result)
	// 	return result, nil
	// }
	logError := ""
	for _, obj := range data {
		if obj["Variable_name"] == "log_error" {
			logError = fmt.Sprint(obj["Value"])
			break
		}
	}
	if strings.Contains(logError, "/stderr.err") {
		result.Status = "Fail"
		result.FailReason = "Value of log_error is " + logError
	} else {
		result.Status = "Pass"

	}
	return result, nil
}

// 6.2 Ensure Log Files are Stored on a Non-System Partition
func CheckLogFiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.2",
		Description: "Ensure Log Files are Stored on a Non-System Partition",
	}
	query := `SELECT @@global.log_bin_basename;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	// if len(data) == 0 {
	// 	result.Status = "Pass"
	// 	log.Print(result)
	// 	return result, nil
	// }
	logFiles := ""
	for _, obj := range data {
		if obj["@@global.log_bin_basename"] != "" {
			logFiles = fmt.Sprint(obj["@@global.log_bin_basename"])
			break
		}
	}
	result.FailReason = utils.GetFailReasonInString(data)
	if strings.HasPrefix(logFiles, "/usr") || strings.HasPrefix(logFiles, "/var") || logFiles == "/" {
		result.Status = "Fail"
		result.FailReason = "Value of @@global.log_bin_basename is " + logFiles
	} else {
		result.Status = "Pass"

	}
	return result, nil
}

// 6.3 Ensure 'log_error_verbosity' is Set to '2'
func CheckLogErrorVerbosity(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.3",
		Description: "Ensure 'log_error_verbosity' is Set to '2'",
	}
	query := `SHOW GLOBAL VARIABLES LIKE 'log_error_verbosity';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	// if len(data) == 0 {
	// 	result.Status = "Pass"
	// 	log.Print(result)
	// 	return result, nil
	// }
	logErrorVerbosity := ""
	for _, obj := range data {
		if obj["Variable_name"] == "log_error_verbosity" {
			logErrorVerbosity = fmt.Sprint(obj["Value"])
			break
		}
	}

	if logErrorVerbosity != "2" {
		result.Status = "Fail"
		result.FailReason = "Value of log_error_verbosity is " + logErrorVerbosity
	} else {
		result.Status = "Pass"

	}
	return result, nil
}

// 6.4 Ensure 'log-raw' is Set to 'OFF'
// mysql --help | grep -i cnf

// 6.5 Ensure Audit Filters Capture Connection Attempts
