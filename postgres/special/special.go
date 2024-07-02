package special

import (
	"context"
	"database/sql"
	"os/exec"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres/helper"
)

// 8.2 CheckPgBackRestInstallation checks if pgBackRest is installed and configured.
func CheckPgBackRestInstallation() helper.CheckHelper {
	result := &model.Result{
		Control:     "8.2",
		Title:       "Ensure the backup and restore tool, 'pgBackRest', is installed and configured",
		Description: "pgBackRest provides robust features and flexibility for PostgreSQL backups.",
		Rationale:   "pgBackRest supports efficient backups on large PostgreSQL databases with features like compression, encryption, and parallel processing.",
		Procedure:   "Run 'pgbackrest' to check if it is installed and to view the general help information.",
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	return helper.NewCheckHelper(result, func(store *sql.DB, ctx context.Context) (*model.Result, error) {
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
	})
}

func CheckPostgresSubdirecotry() helper.CheckHelper {
	result := &model.Result{
		Control: "8.1",
		Title:   "Ensure PostgreSQL subdirectory locations are outside the data cluster",
		Description: `The PostgreSQL cluster is organized to carry out specific tasks in subdirectories. For
		the purposes of performance, reliability, and security some of these subdirectories
		should be relocated outside the data cluster.`,
		Rationale: `Some subdirectories contain information, such as logs, which can be of value to others
		such as developers. Other subdirectories can gain a performance benefit when placed
		on fast storage devices. Other subdirectories contain temporary files created and used
		during processing. Finally, relocating a subdirectory to a separate and distinct partition
		mitigates denial of service and involuntary server shutdown when excessive writes fill
		the data cluster's partition, e.g. pg_wal, pg_log, and temp_tablespaces.`,
		Procedure: "select name, setting from pg_settings where (name ~ '_directory$' or name ~ '_tablespace');",
		Status:    "Manual",
	}

	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		query := `select name, setting from pg_settings where (name ~ '_directory$' or name ~ '_tablespace');`

		data, err := utils.GetTableResponse(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Determine appropriate data, log, and tablespace directories and locations based
		on your organization's security policies. If necessary, relocate all listed directories
		outside the data cluster.`,
			List: []string{
				`If not relocating temp_tablespaces, the temp_file_limit parameter must be
			changed from its default value.`,
				`Ensure file permissions are restricted as much as possible, i.e. only superuser
			read access.`,
				`When directories are relocated to other partitions, ensure that they are of
			sufficient size to mitigate against excessive space utilization.`,
				`Lastly, change the settings accordingly in the postgresql.conf configuration file
			and restart the database cluster for changes to take effect.`,
			},
			Table: data,
		}

		return result, nil
	})
}

func CheckMiscellaneousConfigurationSetting() helper.CheckHelper {
	result := &model.Result{
		Control: "8.3",
		Title:   "Ensure miscellaneous configuration settings are correct",
		Description: `This recommendation covers non-regular, special files, and dynamic libraries.
		PostgreSQL permits local logins via the UNIX DOMAIN SOCKET and, for the most part,
		anyone with a legitimate Unix login account can make the attempt. Limiting PostgreSQL
		login attempts can be made by relocating the UNIX DOMAIN SOCKET to a subdirectory
		with restricted permissions.`,
		Rationale: `The creation and implementation of user-defined dynamic libraries is an extraordinary
		powerful capability. In the hands of an experienced DBA/programmer, it can significantly
		enhance the power and flexibility of the RDBMS; but new and unexpected behavior can
		also be assigned to the RDBMS, resulting in a very dangerous environment in what
		should otherwise be trusted.`,
		Procedure: `select name, setting from pg_settings where name in
		('external_pid_file','unix_socket_directories','shared_preload_libraries',
		'dynamic_library_path','local_preload_libraries','session_preload_libraries');`,
		Status: "Manual",
	}
	return helper.NewCheckHelper(result, func(db *sql.DB, ctx context.Context) (*model.Result, error) {

		query := `select name, setting from pg_settings where name in
				('external_pid_file', 'unix_socket_directories','shared_preload_libraries',
				'dynamic_library_path','local_preload_libraries','session_preload_libraries');`

		data, err := utils.GetTableResponse(db, query)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = err.Error()
			return result, nil
		}

		result.ManualCheckData = model.ManualCheckTableDescriptionAndList{
			Description: `Follow these steps to remediate the configuration:`,
			List: []string{
				`Relocate all files and ensure their permissions are restricted as much as
			possible, i.e. only superuser read access.`,
				`Ensure all directories where these files are located have restricted permissions
			such that the superuser can read but not write.`,
				`Lastly, change the settings accordingly in the postgresql.conf configuration file
			and restart the database cluster for changes to take effect.`,
			},
			Table: data,
		}

		return result, nil
	})
}
