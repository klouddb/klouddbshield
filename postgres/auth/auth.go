package auth

import (
	"context"
	"database/sql"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres/helper"
)

// 4.3 Ensure excessive function privileges are revoked
func CheckFunctionPrivileges() helper.CheckHelper {
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

	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {
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
		result.FailReason = utils.GetFailReasonInString(data)
		return result, nil
	})
}

// 4.5 Use pg_permission extension to audit object permissions (deprecated?)
func CheckObjectPermissions() helper.CheckHelper {
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

	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {
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
	})
}

// 4.6 Ensure the set_user extension is installed
func CheckSetUserExtension() helper.CheckHelper {
	result := &model.Result{
		Control: "4.6",
		Rationale: `Even when reducing and limiting the access to the superuser role as described earlier in this benchmark, it is still difficult to determine who accessed the superuser role and what actions were taken using that role.
		As such, it is ideal to prevent anyone from logging in as the superuser and forcing them to escalate their role.
		This model is used at the OS level by the use of sudo and should be emulated in the database.
		The set_user extension allows for this setup.
		`,
		Procedure: `select * from pg_extension where extname = 'set_user';
		If the extension isn't found, this is a fail.`,
		Description: `PostgreSQL access to the superuser database role must be controlled and audited to prevent unauthorized access.`,
		References: `CIS PostgreSQL 16
		v1.0.0 - 11-07-2023`,
		Title: "Ensure the set_user extension is installed",
	}

	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {
		query := `select * from pg_extension where extname = 'set_user';`

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
	})
}

func CheckPrivilegedAccess() helper.CheckHelper {
	result := &model.Result{
		Control: "4.3",
		Rationale: `By not restricting global administrative commands to superusers only, regular users
		granted excessive privileges may execute administrative commands with unintended
		and undesirable results.`,
		Procedure: `SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolconnlimit, r.rolvaliduntil,
					ARRAY(SELECT b.rolname
						FROM pg_catalog.pg_auth_members m
						JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
						WHERE m.member = r.oid) as memberof, r.rolreplication
					FROM pg_catalog.pg_roles r ORDER BY 1;`,
		Description: `Only superusers should have elevated privileges. PostgreSQL regular, or application,
		users should not possess the ability to create roles, create new databases, manage
		replication, or perform any other action deemed privileged.`,
		Title:  "Ensure excessive administrative privileges are revoked",
		Status: "Manual",
	}

	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "4.2"
		}

		query := `SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolconnlimit, r.rolvaliduntil,
				ARRAY(SELECT b.rolname
					FROM pg_catalog.pg_auth_members m
					JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
					WHERE m.member = r.oid) as memberof, r.rolreplication
				FROM pg_catalog.pg_roles r ORDER BY 1;`

		data, err := utils.GetTableResponse(store, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Please review below list and revoke unnecessary permissions :",
			Table:       data,
		}

		return result, nil
	})
}

func CheckLockoutInactiveAccounts() helper.CheckHelper {
	result := &model.Result{
		Control:   "4.4",
		Rationale: "Only actively used database accounts should be allowed to login to the database.",
		Procedure: `SELECT rolname FROM pg_catalog.pg_roles WHERE rolname !~ '^pg_' AND rolcanlogin;`,
		Description: `If users with database accounts will not be using the database for some time, disabling
		the account will reduce the risk of attacks or inappropriate account usage.`,
		Title:  "Lock Out Accounts if Not Currently in Use",
		Status: "Manual",
	}

	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {
		query := `SELECT rolname FROM pg_catalog.pg_roles WHERE rolname !~ '^pg_' AND rolcanlogin;`

		data, err := utils.GetJSON(store, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		list := []string{}
		for _, v := range data {
			list = append(list, v["rolname"].(string))
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Review the status of below accounts . Inactive accounts should not be shown in the output.",
			List:        list,
		}

		return result, nil
	})
}

func CheckDMLPrivileges() helper.CheckHelper {
	result := &model.Result{
		Control: "4.6",
		Rationale: `Excessive DML grants can lead to unprivileged users changing or deleting information
		without proper authorization.`,
		Procedure: `select t.schemaname, t.tablename, u.usename,
			has_table_privilege(u.usename, t.tablename, 'select') as select,
			has_table_privilege(u.usename, t.tablename, 'insert') as insert,
			has_table_privilege(u.usename, t.tablename, 'update') as update,
			has_table_privilege(u.usename, t.tablename, 'delete') as delete
			from pg_tables t, pg_user u
			where t.schemaname not in ('information_schema','pg_catalog');`,
		Description: `DML (insert, update, delete) operations at the table level should be restricted to only
		authorized users. PostgreSQL manages table-level DML permissions via the GRANT
		statement.`,
		Title:  "Ensure excessive DML privileges are revoked",
		Status: "Manual",
	}
	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "4.4"
		}

		query := `select t.schemaname, t.tablename, u.usename,
		has_table_privilege(u.usename, t.tablename, 'select') as select,
		has_table_privilege(u.usename, t.tablename, 'insert') as insert,
		has_table_privilege(u.usename, t.tablename, 'update') as update,
		has_table_privilege(u.usename, t.tablename, 'delete') as delete
		from pg_tables t, pg_user u
		where t.schemaname not in ('information_schema','pg_catalog');`

		data, err := utils.GetTableResponse(store, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Please review below list and revoke unnecessary DML permissions : ",
			Table:       data,
		}

		return result, nil
	})
}

func CheckRLSSecurityConfiguration() helper.CheckHelper {
	result := &model.Result{
		Control: "4.7",
		Rationale: `If RLS policies and privileges are not configured correctly, users could perform actions
		on tables that they are not authorized to perform, such as inserting, updating, or
		deleting rows.`,
		Procedure: `SELECT usename FROM pg_catalog.pg_user WHERE usebypassrls IS TRUE;`,
		Description: `If you use RLS and apply restrictive policies to certain users, it is important that the
		Bypass RLS privilege not be granted to any unauthorized users. This privilege overrides
		RLS-enabled tables and associated policies. Generally, only superusers and elevated
		users should possess this privilege.`,
		Title:  "Ensure Row Level Security (RLS) is configured correctly",
		Status: "Manual",
	}
	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "4.5"
		}

		query := `SELECT usename FROM pg_catalog.pg_user WHERE usebypassrls IS TRUE;`

		data, err := utils.GetJSON(store, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		list := []string{}
		for _, v := range data {
			list = append(list, v["usename"].(string))
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Please review below output and take necessary action",
			List:        list,
		}

		return result, nil
	})
}

func CheckPredefinedRoles() helper.CheckHelper {
	result := &model.Result{
		Control: "4.9",
		Rationale: `In keeping with the principle of least privilege, judicious use of the PostgreSQL
predefined roles can greatly limit the access to privileged, or superuser, access.`,
		Procedure: `select rolname from pg_roles where rolsuper is true;`,
		Description: `PostgreSQL provides a set of predefined roles that provide access to certain commonly
needed privileged capabilities and information. Administrators can GRANT these roles
to users and/or other roles in their environment, providing those users with access to
the specified capabilities and information. e.g : pg_read_all_data  ,pg_write_all_data etc..`,
		Title:  "Make use of predefined roles",
		Status: "Manual",
	}
	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "4.7"
		}

		query := `select rolname from pg_roles where rolsuper is true;`

		data, err := utils.GetJSON(store, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		list := []string{}
		for _, v := range data {
			list = append(list, v["rolname"].(string))
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Review below  list of all database roles that have superuser access and determine if one or
more of the predefined roles would suffice for the needs of that role:`,
			List: list,
		}

		return result, nil
	})
}
