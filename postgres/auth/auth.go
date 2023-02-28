package auth

import (
	"context"
	"database/sql"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 4.3 Ensure excessive function privileges are revoked
func CheckFunctionPrivileges(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.3",
		Description: "Ensure excessive function privileges are revoked",
	}

	query := `SELECT nspname, proname, proargtypes, prosecdef, rolname,
	proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN
	pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;`

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
	result.Status = "Fail"
	result.FailReason = data
	return result, nil
}

// 4.5 Use pg_permission extension to audit object permissions
func CheckObjectPermissions(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.5",
		Description: "Use pg_permission extension to audit object permissions",
	}

	query := `select * from pg_available_extensions where name ='pg_permissions';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "Got no output, expected pg_permissions extension"
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}

// 4.7 Ensure the set_user extension is installed
func CheckSetUserExtension(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "4.7",
		Description: "Ensure the set_user extension is installed",
	}

	query := `select * from pg_available_extensions where name = 'set_user';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}
	if len(data) == 0 {
		result.Status = "Fail"
		result.FailReason = "Got no output, expected set_user extension"
		return result, nil
	}
	result.Status = "Pass"
	return result, nil
}
