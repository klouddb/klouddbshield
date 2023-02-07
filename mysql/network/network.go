package network

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/klouddb/klouddbshield/mysql/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 8.1 Ensure 'require_secure_transport' is Set to 'ON' and/or 'have_ssl' is Set to 'YES'
func CheckRequireSecureTransport(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "8.1",
		Description: "Ensure 'require_secure_transport' is Set to 'ON' and/or 'have_ssl' is Set to 'YES'",
	}
	query := `select @@require_secure_transport;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	requireSecureTransport := ""
	for _, obj := range data {
		if obj["Variable_name"] == "@@require_secure_transport" {
			requireSecureTransport = fmt.Sprint(obj["Value"])
			break
		}
	}
	if requireSecureTransport == "" {
		requireSecureTransport = "empty"
	}
	if requireSecureTransport == "ON" || requireSecureTransport == "1" {
		result.Status = "Pass"

	} else {
		result.Status = "Fail"
		result.FailReason = "Value of @@require_secure_transport is " + requireSecureTransport
		return result, nil
	}

	query = `SHOW variables WHERE variable_name = 'have_ssl' or variable_name = 'have_openssl';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	haveOpenSSL := ""
	haveSSL := ""
	for _, obj := range data {
		if obj["Variable_name"] == "have_openssl" {
			haveOpenSSL = fmt.Sprint(obj["Value"])
		}
		if obj["Variable_name"] == "have_ssl" {
			haveSSL = fmt.Sprint(obj["Value"])
		}
	}
	if !(haveOpenSSL == "YES" || haveSSL == "YES") {
		result.Status = "Fail"
		result.FailReason = "Value of have_openssl is " + haveOpenSSL + " and Value of have_ssl is " + haveSSL
	}
	return result, nil
}

// 8.2 Ensure 'ssl_type' is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users
//TODO: get output of
// SELECT user, host, ssl_type FROM mysql.user
// WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');

// 8.3 Set Maximum Connection Limits for Server and per User
func CheckMaxConnLimits(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "8.3",
		Description: "Set Maximum Connection Limits for Server and per User",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables
	WHERE VARIABLE_NAME LIKE 'max_%connections';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	maxConnections := ""
	maxUserConnections := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "max_connections" {
			maxConnections = fmt.Sprint(obj["VARIABLE_VALUE"])
		}
		if obj["VARIABLE_NAME"] == "max_user_connections" {
			maxUserConnections = fmt.Sprint(obj["VARIABLE_VALUE"])
		}
	}
	if maxConnections == "" {
		maxConnections = "empty"
	}
	if maxUserConnections == "" {
		maxUserConnections = "empty"
	}
	mc, err1 := strconv.Atoi(maxConnections)
	muc, err2 := strconv.Atoi(maxUserConnections)
	if err1 != nil || err2 != nil || mc < 1 || muc < 1 {
		result.Status = "Fail"
		result.FailReason = "Value of max_connections is " + maxConnections + " and value of max_user_connections is " + maxUserConnections
		return result, nil
	} else {
		result.Status = "Pass"
	}
	query = `select user, host, max_user_connections from mysql.user where user not like
	'mysql.%' and user not like 'root';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}

	for _, obj := range data {
		if obj["Variable_name"] == "max_user_connections" {
			muc, err := strconv.Atoi(fmt.Sprint(obj["Value"]))
			if err != nil || muc < 1 {
				result.Status = "Fail"
				result.FailReason = "Value of max_user_connections is " + fmt.Sprint(obj["Value"])
				break
			}
		}
	}

	return result, nil
}
