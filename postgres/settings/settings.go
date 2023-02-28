package settings

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 6.2 Ensure 'backend' runtime parameters are configured correctly
func CheckSetUserExtension(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.2",
		Description: "Ensure 'backend' runtime parameters are configured correctly",
	}

	query := `SELECT name, setting FROM pg_settings WHERE context IN ('backend','superuser-backend') ORDER BY 1;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	ignoreSystemIndexes := ""
	jitDebuggingSupport := ""
	jitprofilingSupport := ""
	logConnections := ""
	logDisconnections := ""
	postAuthDelay := ""
	for _, obj := range data {
		if obj["name"] == "ignore_system_indexes" {
			ignoreSystemIndexes = fmt.Sprint(obj["setting"])
		}
		if obj["name"] == "jit_debugging_support" {
			jitDebuggingSupport = fmt.Sprint(obj["setting"])
		}
		if obj["name"] == "jit_profiling_support" {
			jitprofilingSupport = fmt.Sprint(obj["setting"])
		}
		if obj["name"] == "log_connections" {
			logConnections = fmt.Sprint(obj["setting"])
		}
		if obj["name"] == "log_disconnections" {
			logDisconnections = fmt.Sprint(obj["setting"])
		}
		if obj["name"] == "post_auth_delay" {
			postAuthDelay = fmt.Sprint(obj["setting"])
		}

	}
	if ignoreSystemIndexes == "off" &&
		jitDebuggingSupport == "off" &&
		jitprofilingSupport == "off" &&
		logConnections == "on" &&
		logDisconnections == "on" &&
		postAuthDelay == "0" {
		result.FailReason = data
		result.Status = "Pass"
		return result, nil
	}
	result.FailReason = data
	result.Status = "Fail"
	return result, nil
}

// 6.7 Ensure FIPS 140-2 OpenSSL Cryptography Is Used
func CheckFIPS(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.7",
		Description: "Ensure FIPS 140-2 OpenSSL Cryptography Is Used",
	}
	cmd := "fips-mode-setup --check"

	outStr, errStr, err := utils.ExecBash(cmd)

	if strings.Contains(outStr, "enabled") {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
		result.Status = "Fail"
		return result, nil
	}
	cmd = "openssl version"

	outStr, errStr, err = utils.ExecBash(cmd)
	if strings.Contains(outStr, "fips") {
		result.Status = "Pass"
	}
	if outStr != "" {
		result.FailReason = outStr
		result.Status = "Fail"

	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	}
	return result, nil
}

// 6.8 Ensure SSL is enabled and configured correctly
func CheckSSL(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.8",
		Description: "Ensure SSL is enabled and configured correctly",
	}

	query := `SHOW ssl;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	ssl := ""
	for _, obj := range data {
		if obj["ssl"] != nil {
			ssl = fmt.Sprint(obj["ssl"])
			break
		}
	}
	if ssl == "off" {
		result.Status = "Fail"
		result.FailReason = data
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 6.9 Ensure the pgcrypto extension is installed and configured correctly
func CheckPGCrypto(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.9",
		Description: "Ensure the pgcrypto extension is installed and configured correctly",
	}

	query := `SELECT * FROM pg_available_extensions WHERE name='pgcrypto';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "pgcrypto not installed"
	}

	result.Status = "Pass"
	return result, nil
}
