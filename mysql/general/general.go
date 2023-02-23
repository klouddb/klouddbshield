package general

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 4.2 Ensure Example or Test Databases are Not Installed on Production Servers
func CheckTestDBOnServer(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.2",
		Description: "Ensure Example or Test Databases are Not Installed on Production Servers",
	}
	query := `SELECT * FROM information_schema.SCHEMATA where SCHEMA_NAME not in
	('mysql','information_schema', 'sys', 'performance_schema');`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Pass"
		return result, nil
	}
	check := map[string]bool{
		"employees": true,
		"world":     true,
		"world_x":   true,
		"sakila":    true,
		"airportdb": true,
		"menagerie": true,
	}
	// result.FailReason = data
	for _, obj := range data {
		for key, value := range obj {
			if check[fmt.Sprint(value)] {
				result.Status = "Fail"
				result.FailReason = "Got unexpected value '" + fmt.Sprint(value) + "' for " + fmt.Sprint(key)
				return result, nil
			}
		}
	}
	result.Status = "Pass"
	return result, nil
}

// 4.3 Ensure 'allow-suspicious-udfs' is Set to 'OFF'
func CheckAllowSuspiciousUdfs(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.3",
		Description: "Ensure 'allow-suspicious-udfs' is Set to 'OFF'",
	}
	cmd := "my_print_defaults mysqld | grep allow-suspicious-udfs"

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr == "" && errStr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Pass"
	} else if err != nil || errStr != "" {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"

	}
	// fmt.Printf("%+v\n", result)
	return result, nil

}

// 4.5 Ensure 'mysqld' is Not Started With '--skip-grant-tables'
func CheckPrefixMySqld(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.5",
		Description: "Ensure 'mysqld' is Not Started With '--skip-grant-tables'",
	}
	query := `show global variables like '%skip-grant-tables%' ;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// if err != nil {
	// 	return nil, err
	// }
	if len(data) == 0 {
		result.Status = "Pass"
		// log.Print(result)
		return result, nil
	}
	// for _, obj := range data {
	// 	if obj["Variable_name"] == "audit_log_file" {
	// 		auditLogFile = fmt.Sprint(obj["Value"])
	// 		break
	// 	}
	// }

	// If you see any of below names in output this is a FAIL if not it is a PASS
	// • employees • world • world_x • sakila • airportdb • menagerie

	// if strings.Contains() {
	// 	result.Status = "Fail"
	// 	result.FailReason = "audit_log_file is " + auditLogFile
	// } else {
	// 	result.Status = "Pass"
	// }
	// log.Print(result)
	return result, nil
}

// 4.6 Ensure Symbolic Links are Disabled
func CheckSymbolicLink(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.6",
		Description: "Ensure Symbolic Links are Disabled",
	}
	query := `SHOW variables LIKE 'have_symlink';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// if err != nil {
	// 	return nil, err
	// }
	// if len(data) == 0 {
	// 	result.Status = "Pass"
	// 	log.Print(result)
	// 	return result, nil
	// }
	haveSymlink := ""
	for _, obj := range data {
		if obj["Variable_name"] == "have_symlink" {
			haveSymlink = fmt.Sprint(obj["Value"])
			break
		}
	}
	if haveSymlink == "DISABLED" {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailReason = "Value of have_symlink is" + haveSymlink
	}
	// If you see any of below names in output this is a FAIL if not it is a PASS
	// • employees • world • world_x • sakila • airportdb • menagerie

	// if strings.Contains() {
	// 	result.Status = "Fail"
	// 	result.FailReason = "audit_log_file is " + auditLogFile
	// } else {
	// 	result.Status = "Pass"
	// }
	// log.Print(result)
	return result, nil
}

// 4.7Ensure the 'daemon_memcached' Plugin is Disabled
func CheckDaemonMemcached(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.7",
		Description: "Ensure the 'daemon_memcached' Plugin is Disabled",
	}
	query := `SELECT * FROM information_schema.plugins WHERE
	PLUGIN_NAME='daemon_memcached';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailReason = "Value of daemon_memcached is" + string(jsonData)
	}
	// log.Print(result)
	return result, nil
}

// 4.8Ensure the 'secure_file_priv' is Configured Correctly
func ChecksecureFilePriv(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.8",
		Description: "Ensure the 'secure_file_priv' is Configured Correctly",
	}
	query := `SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	secureFilePriv := ""
	for _, obj := range data {
		if obj["Variable_name"] == "secure_file_priv" {
			secureFilePriv = fmt.Sprint(obj["Value"])
			break
		}
	}
	if secureFilePriv == "NULL" {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailReason = "Value of secure_file_priv is" + secureFilePriv
	}
	// log.Print(result)
	return result, nil
}

// 4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES'
func CheckSQLMode(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.9",
		Description: "Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES'",
	}
	query := `SHOW VARIABLES LIKE 'sql_mode';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	SQLMode := ""
	for _, obj := range data {
		if obj["Variable_name"] == "sql_mode" {
			SQLMode = fmt.Sprint(obj["Value"])
			break
		}
	}
	if strings.Contains(SQLMode, "STRICT_ALL_TABLES") {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailReason = "Value of sql_mode is:\n" + SQLMode
	}
	// log.Print(result)
	return result, nil
}
