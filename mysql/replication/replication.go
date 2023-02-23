package replication

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 9.2 Ensure 'SOURCE_SSL_VERIFY_SERVER_CERT' is Set to 'YES' or '1'
func CheckSOURCESSL(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "9.2",
		Description: "Ensure 'SOURCE_SSL_VERIFY_SERVER_CERT' is Set to 'YES' or '1'",
	}
	query := `select ssl_verify_server_cert from mysql.slave_master_info;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "No output for the query, expected ssl_verify_server_cert from mysql.slave_master_info"
		return result, nil
	}
	sslVerifyServerCert := ""
	for _, obj := range data {
		if obj["Variable_name"] == "ssl_verify_server_cert" {
			sslVerifyServerCert = fmt.Sprint(obj["Value"])
			break
		}
	}

	if sslVerifyServerCert != "1" {
		result.Status = "Fail"
		result.FailReason = "Value of ssl_verify_server_cert is " + sslVerifyServerCert
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 9.3 Ensure 'master_info_repository' is Set to 'TABLE'
func CheckMasterInfoRepo(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "9.3",
		Description: "Ensure 'master_info_repository' is Set to 'TABLE'",
	}
	query := `select ssl_verify_server_cert from mysql.slave_master_info;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "No output for the query, expected ssl_verify_server_cert from mysql.slave_master_info"
		return result, nil
	}
	sslVerifyServerCert := ""
	for _, obj := range data {
		if obj["Variable_name"] == "ssl_verify_server_cert" {
			sslVerifyServerCert = fmt.Sprint(obj["Value"])
			break
		}
	}

	if sslVerifyServerCert != "1" {
		result.Status = "Fail"
		result.FailReason = "Value of ssl_verify_server_cert is " + sslVerifyServerCert
	} else {
		result.Status = "Pass"
	}
	return result, nil
}
