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
		Control: "4.3",
		Rationale: `Ideally, all application source code should be vetted to validate interactions between the application and the logic in the database, but this is usually not possible or feasible with available resources even if the source code is available.
		The DBA should attempt to obtain assurances from the development organization that this issue has been addressed and should document what has been discovered.
		The DBA should also inspect all application logic stored in the database (in the form of functions, rules, and triggers) for excessive privileges.`,
		Procedure: `SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;
		Any function with a prosecdef value of 't' violates the rule.
		Check prosecdeef column and mark this control as FAIL when you see 't'.`,
		References: `CIS PostgreSQL 16
		v1.0.0 - 11-07-2023`,
		Description: `Privilege elevation must be utilized only where necessary.
		Execute privileges for application functions should be restricted to authorized users only.`,
		Title: "Ensure excessive function privileges are revoked",
	}

	query := `SELECT nspname, proname, proargtypes, prosecdef, rolname,
	proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN
	pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL and prosecdef='t';`

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

// 4.5 Use pg_permission extension to audit object permissions (deprecated?)
func CheckObjectPermissions(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "4.5",
		Rationale: `Auditing permissions in a PostgreSQL database can be intimidating given the default manner in which permissions are presented.
		The pg_permissions extension greatly simplifies this presentation and allows the user to declare what permissions should exist and then report on differences from that ideal.`,
		Procedure: `postgres=# select * from pg_available_extensions where name ='pg_permissions';
		If the extension isn't found, this is a fail.`,
		References: `CIS PostgreSQL 13 Benchmark
v1.0.0 - 02-26-2021`,
		Description: `Using a PostgreSQL extension called pg_permissions it is possible to declare which DB users should have which permissions on a given object and generate a report showing compliance/deviation.`,
		Title:       "Use pg_permission extension to audit object permissions",
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

// 4.6 Ensure the set_user extension is installed
func CheckSetUserExtension(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "4.6",
		Rationale: `Even when reducing and limiting the access to the superuser role as described earlier in this benchmark, it is still difficult to determine who accessed the superuser role and what actions were taken using that role.
		As such, it is ideal to prevent anyone from logging in as the superuser and forcing them to escalate their role.
		This model is used at the OS level by the use of sudo and should be emulated in the database.
		The set_user extension allows for this setup.
		`,
		Procedure: `select * from pg_available_extensions where name = 'set_user';
		If the extension isn't found, this is a fail.`,
		Description: `PostgreSQL access to the superuser database role must be controlled and audited to prevent unauthorized access.`,
		References: `CIS PostgreSQL 16
		v1.0.0 - 11-07-2023`,
		Title: "Ensure the set_user extension is installed",
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
