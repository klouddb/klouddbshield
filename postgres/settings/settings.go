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
		Control: "6.2",
		Rationale: `A denial of service is possible by denying the use of indexes and by slowing down client access to an unreasonable level.
Unsanctioned behavior can be introduced by introducing rogue libraries which can then be called in a database session.
Logging can be altered and obfuscated inhibiting root cause analysis.`,
		Procedure: `SELECT name, setting FROM pg_settings WHERE context IN ('backend','superuser-backend') ORDER BY 1;
		name | setting
		-----------------------+---------
		ignore_system_indexes | off
		jit_debugging_support | off
		jit_profiling_support | off
		log_connections | on
		log_disconnections | on
		post_auth_delay | 0
		
		Validate output to match with above`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
		Description: `In order to serve multiple clients efficiently, the PostgreSQL server launches a new "backend" process for each client. 
		The runtime parameters in this benchmark section are controlled by the backend process. 
		The server's performance, in the form of slow queries causing a denial of service, and the RDBM's auditing abilities for determining root cause analysis can be compromised via these parameters.`,
		Title: "Ensure 'backend' runtime parameters are configured correctly",
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
		Control: "6.7",
		Rationale: `Federal Information Processing Standard (FIPS) Publication 140-2 is a computer security standard developed by a U.S. Government and industry working group for validating the quality of cryptographic modules.
		Use of weak, or untested, encryption algorithms undermine the purposes of utilizing encryption to protect data.
		PostgreSQL uses OpenSSL for the underlying encryption layer.`,
		Procedure: `Step 1
		fips-mode-setup --check
		If FIPS mode is enabled is not displayed, then the system is not FIPS enabled and this is a fail.
		
		Step 2
		openssl version
		If fips is not included in the OpenSSL version, then the system is not FIPS capableand this is a fail.
		
		Both Step 1 and Step 2 should PASS for a final PASS`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
		Description: `Install, configure, and use OpenSSL on a platform that has a NIST certified FIPS 140-2 installation of OpenSSL.
		This provides PostgreSQL instances the ability to generate and validate cryptographic hashes to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owner's requirements.`,
		Title: "Ensure FIPS 140-2 OpenSSL Cryptography Is Used",
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
	if strings.Contains(outStr, "OpenSSL") {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
	}
	return result, nil
}

// 6.8 Ensure SSL is enabled and configured correctly
func CheckSSL(store *sql.DB, ctx context.Context) (*model.Result, error) {

	result := &model.Result{
		Control:   "6.8",
		Rationale: `If SSL is not enabled and configured correctly, this increases the risk of data being compromised in transit.`,
		Procedure: `
		1) Ensure that all ssl related params are updated - ssl , ssl_cert_file , ssl_key_file, ssl_ciphers , ssl_ca_file,.. as needed
		2) Ensure that your hba file has hostssl clause (one example entry below)
			# TYPE DATABASE USER ADDRESS METHOD
			hostssl xxx xxxx x.x.x.x/x scram-sha-256
		3) A self-signed certificate can be used for testing, but a certificate signed by a certificate
		authority (CA) (either one of the global CAs or a local one) should be used in production so
		that clients can verify the server's identity.
		`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
		Description: `SSL on a PostgreSQL server should be enabled (set to on) and configured to encrypt TCP traffic to and from the server.`,
		Title:       "Ensure SSL is enabled and configured correctly",
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

// 6.9 CheckTLSVersions ensures that TLSv1.0 and TLSv1.1 are disabled.
func CheckTLSVersions(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "6.9",
		Title:   "Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled",
		Description: `Transport Layer Security (TLS), and its predecessor Secure Sockets Layer (SSL) are 
		cryptographic protocols which can be used to encrypt data sent between client and server.`,
		Rationale: `The TLSv1.0 protocol is vulnerable to the BEAST attack and TLSv1.1 does not support AEAD. 
		Disabling these older versions enhances security.`,
		Procedure: "Check that the 'ssl_min_protocol_version' setting in PostgreSQL is set to either TLSv1.2 or TLSv1.3.",
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Query to fetch the minimum TLS protocol version
	query := "SHOW ssl_min_protocol_version;"

	data, err := utils.GetJSON(db, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	minProtocol := ""
	for _, obj := range data {
		if val, ok := obj["ssl_min_protocol_version"]; ok {
			minProtocol = fmt.Sprint(val)
			break
		}
	}

	// Validate the minimum protocol version
	if minProtocol == "TLSv1.2" || minProtocol == "TLSv1.3" {
		result.Status = "Pass"
		return result, nil
	}

	result.Status = "Fail"
	result.FailReason = fmt.Sprintf("Current ssl_min_protocol_version is %s, which is not secure enough.", minProtocol)
	return result, nil
}

// 6.10 CheckSSLCiphers ensures that only strong and secure SSL/TLS ciphers are configured.
func CheckSSLCiphers(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "6.10",
		Title:       "Ensure Weak SSL/TLS Ciphers Are Disabled",
		Description: "Verifies that only secure SSL/TLS ciphers are enabled in the PostgreSQL configuration.",
		Rationale: `To protect against various cryptographic attacks and ensure data confidentiality and integrity, 
		only strong ciphers should be used.`,
		Procedure: "Verify the ssl_ciphers setting in the postgresql.conf to ensure it includes only secure ciphers.",
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Define allowed ciphers
	allowedCiphers := map[string]bool{
		"TLS_AES_256_GCM_SHA384":        true,
		"TLS_AES_128_GCM_SHA256":        true,
		"TLS_AES_128_CCM_SHA256":        true,
		"TLS_CHACHA20_POLY1305_SHA256":  true,
		"ECDHE-ECDSA-AES256-CCM":        true,
		"ECDHE-ECDSA-AES128-CCM":        true,
		"DHE-RSA-AES256-CCM":            true,
		"DHE-RSA-AES128-CCM":            true,
		"ECDHE-RSA-AES256-GCM-SHA384":   true,
		"ECDHE-RSA-AES128-GCM-SHA256":   true,
		"ECDHE-ECDSA-AES256-GCM-SHA384": true,
		"ECDHE-ECDSA-AES128-GCM-SHA256": true,
		"DHE-DSS-AES256-GCM-SHA384":     true,
		"DHE-DSS-AES128-GCM-SHA256":     true,
		"DHE-RSA-AES256-GCM-SHA384":     true,
		"DHE-RSA-AES128-GCM-SHA256":     true,
		"ECDHE-ECDSA-CHACHA20-POLY1305": true,
		"ECDHE-RSA-CHACHA20-POLY1305":   true,
		"DHE-RSA-CHACHA20-POLY1305":     true,
	}

	// Query the current ssl_ciphers setting
	var cipherSetting string
	err := db.QueryRowContext(ctx, "SHOW ssl_ciphers;").Scan(&cipherSetting)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf("Error fetching ssl_ciphers setting: %v", err)
		return result, nil
	}

	// Check each cipher in the setting
	ciphers := strings.Split(cipherSetting, ":")
	for _, cipher := range ciphers {
		if _, ok := allowedCiphers[cipher]; !ok {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Insecure cipher found: %s", cipher)
			return result, nil
		}
	}

	result.Status = "Pass"
	return result, nil
}

// 6.9/6.11 Ensure the pgcrypto extension is installed and configured correctly
func CheckPGCrypto(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "6.9",
		Rationale: `The PostgreSQL pgcrypto extension provides cryptographic functions for PostgreSQL and is intended to 
		address the confidentiality and integrity of user and system information at rest in non-mobile devices.`,
		Procedure: `SELECT * FROM pg_available_extensions WHERE name='pgcrypto';
		If data in the database requires encryption and pgcrypto is not available, this is a fail.`,
		References: `CIS PostgreSQL 16
		v1.0.0 - 11-07-2023`,
		Description: `PostgreSQL must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of 
		organization-defined information at rest (to include, at aminimum, PII and classified information) on organization-defined 
		information system components.`,
		Title: "Ensure the pgcrypto extension is installed and configured correctly",
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
