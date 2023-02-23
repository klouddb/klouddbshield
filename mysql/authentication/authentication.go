package authentication

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 7.1 Ensure default_authentication_plugin is Set to a Secure Option
func CheckDefaultAuthPlugin(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "7.1",
		Description: "Ensure default_authentication_plugin is Set to a Secure Option",
	}
	query := `SHOW VARIABLES WHERE Variable_name = 'default_authentication_plugin';`

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
	defaultAuthenticationPlugin := ""
	for _, obj := range data {
		if obj["Variable_name"] == "default_authentication_plugin" {
			defaultAuthenticationPlugin = fmt.Sprint(obj["Value"])
			break
		}
	}

	if defaultAuthenticationPlugin == "mysql_native_password" {
		result.Status = "Fail"
		result.FailReason = "Value of log_error_verbosity is " + defaultAuthenticationPlugin
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 7.2 Ensure Passwords are Not Stored in the Global Configuration
// mysql --help | grep cnf

// 7.3 Ensure Passwords are Set for All MySQL Accounts
func CheckPassForAllAcc(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "7.3",
		Description: "Ensure Passwords are Set for All MySQL Accounts",
	}
	query := `SELECT User,host
	FROM mysql.user
	WHERE (plugin IN('mysql_native_password', 'mysql_old_password','')
	AND (LENGTH(authentication_string) = 0
	OR authentication_string IS NULL))
	OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);`

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
		// log.Print(result)
		return result, nil
	}

	result.Status = "Fail"
	result.FailReason = "There are few accounts without password set: " + string(jsonData)

	return result, nil
}

// 7.4 Set 'default_password_lifetime' to Require a Yearly Password Change
func CheckDPLPassExp(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "7.4",
		Description: "Set 'default_password_lifetime' to Require a Yearly Password Change",
	}
	query := `SHOW VARIABLES LIKE 'default_password_lifetime';`

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
	defaultPasswordLifetime := ""
	for _, obj := range data {
		if obj["Variable_name"] == "default_password_lifetime" {
			defaultPasswordLifetime = fmt.Sprint(obj["Value"])
			break
		}
	}

	if i, err := strconv.Atoi(defaultPasswordLifetime); err != nil || i < 364 {
		result.Status = "Fail"
		result.FailReason = "Value of default_password_lifetime is " + defaultPasswordLifetime
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 7.5 Ensure Password Complexity Policies are in Place
func ChecPassComplexPolicies(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "7.5",
		Description: "Ensure Password Complexity Policies are in Place",
	}
	query := `select * from mysql.component where component_urn like '%validate_password';`

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
		result.FailReason = "No Password Complexity Policies"
		return result, nil
	}

	query = `SHOW VARIABLES LIKE 'validate_password%';`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// if len(data) == 0 {
	// 	result.Status = "Fail"
	// 	result.FailReason = "not found validate_password for Password Complexity Policies"
	// 	return result, nil
	// }
	/*
	   • validate_password.length should be 14 or more
	   • validate_password.check_user_name should be ON
	   • validate_password.policy should be STRONG
	*/
	length := ""
	check_user_name := ""
	policy := ""
	for _, obj := range data {
		if obj["Variable_name"] == "validate_password.length" {
			length = fmt.Sprint(obj["Value"])
		}
		if obj["Variable_name"] == "validate_password.check_user_name" {
			check_user_name = fmt.Sprint(obj["Value"])
		}
		if obj["Variable_name"] == "validate_password.policy" {
			policy = fmt.Sprint(obj["Value"])
		}
	}
	passwordLength, _ := strconv.Atoi(length)
	// //TODO: get output of SHOW VARIABLES LIKE 'validate_password%';
	if passwordLength < 14 || check_user_name != "ON" || policy != "STRONG" {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf("Got unexpected result from validate_password:\nvalidate_password.length=%s\nvalidate_password.check_user_name=%s\nvalidate_password.policy=%s",
			length, check_user_name, policy)
	} else {
		result.Status = "Pass"
	}
	return result, nil
}

// 7.6 Ensure No Users Have Wildcard Hostnames
func ChecWildcardHostnames(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "7.6",
		Description: "Ensure No Users Have Wildcard Hostnames",
	}
	query := `SELECT user, host FROM mysql.user WHERE host = '%';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	if len(data) != 0 {
		result.Status = "Fail"
		result.FailReason = "Users Have Wildcard Hostnames"
		return result, nil
	}

	result.Status = "Pass"
	return result, nil
}

// 7.7 Ensure No Anonymous Accounts Exist
func ChecAnonymousAccounts(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "7.7",
		Description: "Ensure No Anonymous Accounts Exist",
	}
	query := `SELECT user,host FROM mysql.user WHERE user = '';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	// jsonData, err := json.Marshal(data)
	// log.Print(string(jsonData))
	if len(data) != 0 {
		result.Status = "Fail"
		result.FailReason = "Anonymous Accounts Exist"
		return result, nil
	}

	result.Status = "Pass"
	return result, nil
}
