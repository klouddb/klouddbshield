package connection

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres/helper"
)

// CheckConnectionLimits checks if per-account connection limits are set appropriately.
func CheckConnectionLimits() helper.CheckHelper {
	result := &model.Result{
		Control:     "5.5",
		Title:       "Ensure per-account connection limits are used",
		Description: "Limiting concurrent connections to a PostgreSQL server can be used to reduce the risk of Denial of Service (DoS) attacks.",
		Rationale:   "Limiting the number of concurrent sessions at the user level helps to reduce the risk of DoS attacks.",
		Procedure: `To check the connection limits for all users, run the following:
		SELECT rolname
		FROM pg_roles
		WHERE rolname NOT LIKE 'pg_%';`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {
		// Query to fetch role names and their connection limits
		query := `SELECT rolname
	FROM pg_roles
	WHERE rolconnlimit = -1 AND rolname NOT LIKE 'pg_%';`

		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			result.FailReason = fmt.Sprintf("Error executing query: %v", err)
			result.Status = "Fail"
			return result, nil
		}
		defer rows.Close()

		// Build a list of roles with no connection limit set (i.e., limit of -1)
		var rolesWithNoLimit []string
		for rows.Next() {
			var rolname string
			if err := rows.Scan(&rolname); err != nil {
				result.FailReason = fmt.Sprintf("Error scanning row: %v", err)
				result.Status = "Fail"
				return result, nil
			}
			rolesWithNoLimit = append(rolesWithNoLimit, rolname)
		}

		// Check if there were any roles with no limit
		if len(rolesWithNoLimit) > 0 {
			result.FailReason = "Users with unlimited connection limits: " + strings.Join(rolesWithNoLimit, ", ")
			result.Status = "Fail"
		} else {
			result.Status = "Pass"
		}

		return result, nil
	})
}

// CheckPasswordInCommandline Do Not Specify Passwords in the Command Line
func CheckPasswordInCommandline() helper.CheckHelper {
	result := &model.Result{
		Control: "5.1",
		Title:   "Do Not Specify Passwords in the Command Line",
		Description: `When a command is executed on the command line, for example
• psql postgresql://postgres:PASSWORD@host
the password may be visible in the user's shell/command history or in the process list,
thus exposing the password to other entities on the server.`,
		Rationale: `If the password is visible in the process list or user's shell/command history, an attacker
will be able to access the PostgreSQL database using the stolen credentials.`,
		Procedure: `ps -few | grep -i psql`,
		Status:    "Manual",
	}
	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {

		cmd := "ps -few | grep -i psql"

		outStr, errStr, err := utils.ExecBash(cmd)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
			return result, nil
		}

		// TODO not manual
		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Review below output and see if you specified any passwords in command line . If the output is empty it is a PASS",
			List:        strings.Split(outStr, "\n"),
		}

		return result, nil
	})
}

// CheckPostgresIPBound Ensure PostgreSQL is Bound to an IP Address.
func CheckPostgresIPBound() helper.CheckHelper {
	result := &model.Result{
		Control: "5.2",
		Title:   "Ensure PostgreSQL is Bound to an IP Address",
		Description: `By default, listen_addresses is set to localhost which prevents any and all remote
TCP connections to the PostgreSQL port.`,
		Rationale: `Limiting the IP addresses that PostgreSQL listens on provides additional restrictions on
where client applications/users can connect from.`,
		Procedure: `SHOW listen_addresses`,
		Status:    "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		query := `SHOW listen_addresses;`

		list, err := utils.GetListFromQuery(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Error executing query: %v", err)
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Review below output and make sure you restrict access as much as possible(Using * or allowing all access is not recommended) :",
			List:        list,
		}

		return result, nil
	})
}

// CheckLocalSocketLogin Ensure login via "local" UNIX Domain Socket is configured correctly
func CheckLocalSocketLogin() helper.CheckHelper {
	result := &model.Result{
		Control: "5.3",
		Title:   `Ensure login via "local" UNIX Domain Socket is configured correctly`,
		Description: `A remote host login, via SSH, is arguably the most secure means of remotely accessing
and administering the PostgreSQL server. Once connected to the PostgreSQL server,
using the psql client, via UNIX DOMAIN SOCKETS, while using the peer authentication
method is the most secure mechanism available for local database connections.`,
		Rationale: `Review peer access - Only give PEER access to needed accounts`,
		Procedure: `SELECT * FROM pg_hba_file_rules where auth_method='peer';`,
		Status:    "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "5.1"
		}

		query := `SELECT * FROM pg_hba_file_rules where auth_method='peer';`
		data, err := utils.GetTableResponse(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Review below output and see hba entries for PEER . Restrict PEER access (According to your Org standards) :`,
			Table:       data,
		}
		return result, nil
	})
}

// CheckHostSocketLogin Ensure login via "local" UNIX Domain Socket is configured correctly
func CheckHostSocketLogin() helper.CheckHelper {
	result := &model.Result{
		Control: "5.4",
		Title:   `Ensure login via "host" TCP/IP Socket is configured correctly`,
		Description: `A large number of authentication METHODs are available for hosts connecting using
TCP/IP sockets,`,
		Rationale: `Newly created data clusters are empty of data and have only one user account, the
superuser. By default, the data cluster superuser is named after the UNIX account
postgres. Login authentication can be tested via TCP/IP SOCKETS by any UNIX user
account from the local host.`,
		Procedure: `SELECT * FROM pg_hba_file_rules where auth_method<>'peer';`,
		Status:    "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "5.2"
		}

		query := `SELECT * FROM pg_hba_file_rules where auth_method<>'peer';`
		data, err := utils.GetTableResponse(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: "Review below accounts using TCP/IP method and make sure they comply with your standards",
			Table:       data,
		}

		return result, nil
	})
}

func CheckPasswordComplexity() helper.CheckHelper {
	result := &model.Result{
		Control: "5.6",
		Title:   `Ensure Password Complexity is configured`,
		Description: `Password complexity configuration is crucial to restrict unauthorized access to data. By
default, PostgreSQL doesn’t provide for password complexity.`,
		Rationale: `Having strong password management for your locally-authenticated PostgreSQL
accounts will protect against attackers' brute force techniques.`,
		Procedure: `"SHOW password_encryption ;
SELECT usename, passwd FROM pg_shadow WHERE passwd IS NULL AND passwd NOT LIKE 'SCRAM-SHA-256%';"`,
		Status: "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		if model.IsFromVersion(ctx, []string{"15", "16"}) {
			result.Control = "5.3"
		}

		query := `SHOW password_encryption ;`
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Error executing query: %v", err)
			return result, nil
		}

		var passwordEncryption []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				result.Status = "Fail"
				result.FailReason = fmt.Sprintf("Error scanning row: %v", err)
				return result, nil
			}

			passwordEncryption = append(passwordEncryption, v)
		}

		query = `SHOW shared_preload_libraries;`
		rows, err = db.QueryContext(ctx, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Sprintf("Error executing query: %v", err)
			return result, nil
		}

		var preloadLibraries []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				result.Status = "Fail"
				result.FailReason = fmt.Sprintf("Error scanning row: %v", err)
				return result, nil
			}
			preloadLibraries = append(preloadLibraries, v)
		}

		query = `SELECT usename, passwd FROM pg_shadow WHERE passwd IS NULL AND passwd NOT LIKE 'SCRAM-SHA-256%';`
		data, err := utils.GetTableResponse(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Review below output to make sure extensions like passwordcheck are used . Also check for password encryption configured:
		password_encryption: ` + strings.Join(passwordEncryption, ", ") + ` and
		shared_preload_libraries: ` + strings.Join(preloadLibraries, ", "),
			Table: data,
		}

		return result, nil
	})
}
