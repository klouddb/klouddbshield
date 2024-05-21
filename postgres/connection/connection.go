package connection

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
)

// CheckConnectionLimits checks if per-account connection limits are set appropriately.
func CheckConnectionLimits(db *sql.DB, ctx context.Context) (*model.Result, error) {
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
}
