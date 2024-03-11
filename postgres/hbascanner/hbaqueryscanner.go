package hbascanner

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

func QueryTrustInMethod(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check if Trust auth method is being used ",
		Description: "Usage of Trust method is not secure",
		Control:     1,
		Procedure: `
 		Method 1-
 		select count(*) from pg_hba_file_rules where
 		auth_method='trust' or auth_method='TRUST';
 		If the count is greater than 0 this is a FAIL
 		Method 2-
 		Manually check your hba file to see if it contains ‘trust’
 		under auth-method`,
	}
	query := `select * from pg_hba_file_rules where
 	auth_method='trust' or auth_method='TRUST';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}

	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryAllInDatabase(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check if ‘all’ is used under database field ",
		Description: "Follow the least privilege method - Be specific and give the needed database(s) and not all",
		Control:     2,
		Procedure: `
		Method 1 - 
		select count(*) from pg_hba_file_rules where 
		database='all';
		If the count is greater than 0 this is a FAIL
		Method 2 - 
		Manually check your hba file to see if it contains ‘all’ 
		under database`,
	}
	query := `select * from pg_hba_file_rules where 
	'all'=any(database);`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryAllInUser(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Description: "Follow the least privilege method - Be specific and give the needed user(s) and not all",
		Control:     3,
		Title:       "Check if ‘all’ is used under user column",
		Procedure: `
		Method 1 - 
		select count(*) from pg_hba_file_rules where 
		user='all';
		If the count is greater than 0 this is a FAIL
		Method 2 - 
		Manually check your hba file to see if it contains ‘all’ 
		under user`,
	}
	query := `select * from pg_hba_file_rules where 'all'=any(user_name);`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryMD5InMethod(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check if md5 auth method is being used",
		Description: "Better to use scram-sha-256",
		Control:     4,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where 
		auth_method='md5';
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘md5’
		under auth-method`,
	}
	query := `select * from pg_hba_file_rules where 
	auth_method='md5';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryPeerInMethod(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check if peer auth method is being used ",
		Description: "Review the lines in hba containing peer method.\nAlthough peer method might be ok to use, \nplease check the users and the hba lines to review furthe",
		Control:     5,
		Procedure: `
		Method 1-
		select * from pg_hba_file_rules where 
		auth_method='peer';
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘md5’
		under auth-method`,
	}
	query := `select * from pg_hba_file_rules where 
	auth_method='peer';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryIdentInMethod(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check if ident auth method is being used ",
		Description: "Usage of Trust method is might not be secure",
		Control:     6,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where auth_method='ident';
		
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘ident’ under auth-method
		`,
	}
	query := `select * from pg_hba_file_rules where 
	auth_method='ident';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryPasswordInMethod(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check if password auth method is being used ",
		Description: "Usage of password method is might not be secure",
		Control:     7,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where auth_method='password';
		
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘password’ under auth-method
		`,
	}
	query := `select * from pg_hba_file_rules where 
	auth_method='password';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryType(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "Check for the presence of host under TYPE column (hostssl should be used for SSL)",
		Description: "Better to enforce ssl to secure your connections - use hostssl instead of host (after enabling ssl)",
		Control:     8,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where type='host';
		
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘host’ under type field
		`,
	}
	query := `select * from pg_hba_file_rules where type='host';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func QueryIPPrivilege(store *sql.DB, ctx context.Context) (*model.HBAScannerResult, error) {
	result := model.HBAScannerResult{
		Title:       "0.0.0.0/0 (IPv4) and ::0/0 (IPv6) in address field",
		Description: "Follow the least privilege method - Be specific and give the needed ip(s) and not all",
		Control:     9,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where address IN('0.0.0.0/0','::0/0');
		
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains 0.0.0.0/0 (IPv4) and ::0/0 (IPv6) in address field
		`,
	}
	query := `select * from pg_hba_file_rules where address IN('0.0.0.0/0','::0/0');`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {

		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	for _, obj := range data {
		result.FailRows = append(result.FailRows, getString(obj))
		if obj["line_number"] != nil {
			result.FailRowsLineNums = append(result.FailRowsLineNums, int(obj["line_number"].(int64)))
		}
	}

	result.FailRowsInString = strings.Join(result.FailRows, "\n")

	return &result, nil
}
func getString(obj map[string]interface{}) string {
	line := " "
	if obj["type"] == nil {
		obj["type"] = "	"
	}
	if obj["database"] == nil {
		obj["database"] = "	"
	}
	if obj["username"] == nil {
		obj["username"] = "	"
	}
	if obj["address"] == nil {
		obj["address"] = "	"
	}
	if obj["auth_method"] == nil {
		obj["auth_method"] = "	"
	}
	line += fmt.Sprint(obj["type"], "	")
	line += fmt.Sprint(obj["database"], "	")
	line += fmt.Sprint(obj["username"], "	")
	line += fmt.Sprint(obj["address"], "	")
	line += fmt.Sprint(obj["auth_method"], "	")
	return line
}
