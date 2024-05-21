package special

import (
	"context"
	"database/sql"
	"os/exec"
	"strings"

	"github.com/klouddb/klouddbshield/model"
)

// 8.2 CheckPgBackRestInstallation checks if pgBackRest is installed and configured.
func CheckPgBackRestInstallation(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "8.2",
		Title:       "Ensure the backup and restore tool, 'pgBackRest', is installed and configured",
		Description: "pgBackRest provides robust features and flexibility for PostgreSQL backups.",
		Rationale:   "pgBackRest supports efficient backups on large PostgreSQL databases with features like compression, encryption, and parallel processing.",
		Procedure:   "Run 'pgbackrest' to check if it is installed and to view the general help information.",
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Attempt to run 'pgbackrest' to check if it's installed
	cmd := exec.Command("pgbackrest")
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Check for common command not found errors
	if err != nil && strings.Contains(outputStr, "command not found") {
		result.Status = "Fail"
		result.FailReason = "pgBackRest is not installed."
		return result, nil
	}

	// Check for valid response indicating pgBackRest is installed
	if strings.Contains(outputStr, "pgBackRest") {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailReason = "Unexpected output from pgBackRest, it may not be configured correctly."
	}

	return result, nil
}
