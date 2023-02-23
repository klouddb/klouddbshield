package installation

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 2.1.5 Point-in-Time Recovery
func CheckPointInTimeRec(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.1.5",
		Description: "Point-in-Time Recovery",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - Log Expiration' as Note
	FROM performance_schema.global_variables where variable_name =
	'binlog_expire_logs_seconds';`

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
		result.FailReason = "No output for the query, expected binlog_expire_logs_seconds from performance_schema.global_variables"
		return result, nil
	}
	binlogExpireLogsSeconds := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "binlog_expire_logs_seconds" {
			binlogExpireLogsSeconds = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}

	if binlogExpireLogsSeconds == "0" || binlogExpireLogsSeconds == "" {
		result.Status = "Fail"
		result.FailReason = "Value of binlog_expire_logs_seconds is " + binlogExpireLogsSeconds
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 2.2.1 Ensure Binary and Relay Logs are Encrypted
func CheckBinaryRelayLogs(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.2.1",
		Description: "Ensure Binary and Relay Logs are Encrypted",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - At Rest Encryption' as Note
	FROM performance_schema.global_variables where variable_name =
	'binlog_encryption';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
		return result, nil
	}
	binlogEncryption := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "binlog_encryption" {
			binlogEncryption = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}

	if binlogEncryption == "0" || binlogEncryption == "" || binlogEncryption == "OFF" {
		result.Status = "Fail"
		result.FailReason = "Value of binlog_encryption is " + binlogEncryption
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 2.7 Ensure 'password_lifetime' is Less Than or Equal to '365'
func CheckDefaultPassLt(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.7",
		Description: "Ensure 'password_lifetime' is Less Than or Equal to '365'",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables where VARIABLE_NAME like
	'default_password_lifetime';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
	// 	return result, nil
	// }
	defaultPasswordLifetime := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "default_password_lifetime" {
			defaultPasswordLifetime = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}
	dfl, err := strconv.Atoi(defaultPasswordLifetime)
	if err != nil || dfl > 365 {
		result.Status = "Fail"
		result.FailReason = "Value of default_password_lifetime is " + defaultPasswordLifetime
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}

// 2.8 Ensure Password Resets Require Strong Passwords
func CheckResetPassLt(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.8",
		Description: "Ensure Password Resets Require Strong Passwords",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables where VARIABLE_NAME in
	('password_history', 'password_reuse_interval');`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
	// 	return result, nil
	// }
	passwordHistory := ""
	passwordReuseInterval := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "password_history" {
			passwordHistory = fmt.Sprint(obj["VARIABLE_VALUE"])
		}
		if obj["VARIABLE_NAME"] == "password_reuse_interval" {
			passwordReuseInterval = fmt.Sprint(obj["VARIABLE_VALUE"])
		}
	}
	ph, err1 := strconv.Atoi(passwordHistory)
	pri, err2 := strconv.Atoi(passwordReuseInterval)
	if err1 != nil || err2 != nil || ph < 5 || pri < 365 {
		result.Status = "Fail"
		result.FailReason = "Value of password_history is " + passwordHistory + " and password_reuse_interval is " + passwordReuseInterval
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}

// 2.9 Require Current Password for Password Reset
func CheckCurrentPassLt(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.9",
		Description: "Require Current Password for Password Reset",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables where VARIABLE_NAME in
	('password_require_current');`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
	// 	return result, nil
	// }
	passwordRequireCurrent := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "password_require_current" {
			passwordRequireCurrent = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}

	if passwordRequireCurrent != "ON" {
		result.Status = "Fail"
		result.FailReason = "Value of password_require_current is " + passwordRequireCurrent
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}

// 2.12 Ensure AES Encryption Mode for AES_ENCRYPT/AES_DECRYPT is Configured Correctly
func CheckBlockEncryp(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.12",
		Description: "Ensure AES Encryption Mode for AES_ENCRYPT/AES_DECRYPT is Configured Correctly",
	}
	query := `select @@block_encryption_mode;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
	// 	return result, nil
	// }
	blockEncryptionMode := ""
	for _, obj := range data {
		if obj["@@block_encryption_mode"] != nil {
			blockEncryptionMode = fmt.Sprint(obj["@@block_encryption_mode"])
			break
		}
	}

	if !strings.HasPrefix(blockEncryptionMode, "aes-256") {
		result.Status = "Fail"
		result.FailReason = "Value of block_encryption_mode is " + blockEncryptionMode
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}

// 2.14 Ensure MySQL is Bound to an IP Address
func CheckBindAddr(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.14",
		Description: "Ensure MySQL is Bound to an IP Address",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables
	WHERE VARIABLE_NAME = 'bind_address';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "No output for the query, expected bind_address from performance_schema.global_variables"
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}

// 2.15 Limit Accepted Transport Layer Security (TLS) Versions
func CheckTLS(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.15",
		Description: "Limit Accepted Transport Layer Security (TLS) Versions",
	}
	query := `select @@tls_version;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	tlsVersion := ""
	for _, obj := range data {
		if obj["@@tls_version"] != nil {
			tlsVersion = fmt.Sprint(obj["@@tls_version"])
			break
		}
	}
	listOftlsVersion := strings.Split(tlsVersion, ",")
	for _, value := range listOftlsVersion {
		if value == "TLSv1.1" || value == "TLSv1" {
			result.Status = "Fail"
			result.FailReason = "Value of tls_version is " + tlsVersion
			return result, nil
		}
	}

	query = `select * from performance_schema.status_by_thread where VARIABLE_NAME like
	'ssl_version';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	sslVersion := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] != "Ssl_version" {
			sslVersion = fmt.Sprint(obj["VARIABLE_VALUE"])
			break
		}
	}
	listOfsslVersion := strings.Split(tlsVersion, ",")
	for _, value := range listOfsslVersion {
		if value == "TLSv1.1" || value == "TLSv1" {
			result.Status = "Fail"
			result.FailReason = "Value of sslVersion is " + sslVersion
			return result, nil
		}
	}

	result.Status = "Pass"

	return result, nil
}

// 2.16 Require Client-Side Certificates (X.509)
func CheckClientCert(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.16",
		Description: "Require Client-Side Certificates (X.509)",
	}
	query := `select user, host, ssl_type from mysql.user where user not in
	('mysql.infoschema', 'mysql.session', 'mysql.sys');`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	result.FailReason = data
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
	// 	return result, nil
	// }
	sslType := []string{}
	for _, obj := range data {
		if obj["user"] != nil {
			sslType = append(sslType, fmt.Sprint(obj["ssl_type"]))
		}
	}
	for _, value := range sslType {
		if value != "X509" || value == "SSL" {
			result.Status = "Fail"
			result.FailReason = data
			return result, nil
		}
	}
	result.Status = "Pass"
	return result, nil
}

// 2.17 Ensure Only Approved Ciphers are Used
func CheckSSLTLS(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.17",
		Description: "Ensure Only Approved Ciphers are Used",
	}
	query := `SELECT VARIABLE_NAME, VARIABLE_VALUE
	FROM performance_schema.global_variables
	WHERE VARIABLE_NAME IN ('ssl_cipher', 'tls_ciphersuites');`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "No output for the query, expected binlog_encryption from performance_schema.global_variables"
	// 	return result, nil
	// }
	sslCipher := ""
	tlsCiphersuites := ""
	for _, obj := range data {
		if obj["VARIABLE_NAME"] == "ssl_cipher" {
			sslCipher = fmt.Sprint(obj["VARIABLE_VALUE"])

		}
		if obj["VARIABLE_NAME"] == "tls_ciphersuites" {
			tlsCiphersuites = fmt.Sprint(obj["VARIABLE_VALUE"])

		}
	}

	if sslCipher != "ECDHE-ECDSA-AES128-GCM-SHA256" || tlsCiphersuites == "TLS_AES_256_GCM_SHA384" {
		result.Status = "Fail"
		result.FailReason = "Value of sslCipher is " + sslCipher + "\nValue of tls_ciphersuites is " + tlsCiphersuites
		return result, nil
	}

	result.Status = "Pass"

	return result, nil
}
