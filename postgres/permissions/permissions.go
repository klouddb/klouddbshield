package permissions

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 2.1 Ensure the file permissions mask is correct
func CheckSystemdServiceFiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:   "2.1",
		Title:     "Ensure the file permissions mask is correct",
		Rationale: `The Linux OS defaults the umask to 0022, which means the owner and primary group can read and write the file, and other accounts are permitted to read the file.`,
		Procedure: `# whoami
		root
		# su - postgres
		# whoami
		postgres
		# umask
		0022
		As discussed above umask of 077 can help`,
		References: `CIS PostgreSQL 16
		v1.0.0 - 11-07-2023`,
		Description: `The Linux OS defaults the umask to 0022, which means the owner and primary group
		can read and write the file, and other accounts are permitted to read the file. Not
		explicitly setting the umask to a value as restrictive as 0077 allows other users to read,
		write, or even execute files and scripts created by the postgres user account.`,
	}
	cmd := "su -c 'umask' -l postgres"

	out, errStr, err := utils.ExecBash(cmd)
	if errStr != "" && err != nil {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if strings.Contains(out, "0022") || strings.Contains(out, "0002") {
		result.FailReason = "umask for postgres user is " + out
		result.Status = "Fail"
		return result, nil
	}
	if out == "" {
		result.FailReason = "Unable to fetch umask"
		result.Status = "Fail"
		return result, nil
	}

	result.Status = "Pass"
	return result, nil
}

// 2.2 EnsureExtensionDirOwnershipAndPermissions checks the permissions and ownership of the PostgreSQL extension directory. (v13)
func EnsureExtensionDirOwnershipAndPermissions_v13(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "2.2",
		Title:   "Ensure extension directory has appropriate ownership and permissions",
		Description: `The extension directory is the location of the PostgreSQL extensions,
		which are storage engines or user defined functions (UDFs).`,
		Rationale: `Limiting the accessibility of these objects will protect the confidentiality, 
		integrity, and availability of the PostgreSQL database. If someone can modify extensions, 
		then these extensions can be used to execute illicit instructions.`,
		Procedure: `Check the ownership and permissions of the PostgreSQL extension directory to ensure 
		it is owned by root with permissions 
		drwxr-xr-x.`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Get the PostgreSQL shared directory
	sharedDirCmd := "sudo /usr/pgsql-13/bin/pg_config --sharedir"
	sharedDir, errStr, err := utils.ExecBash(sharedDirCmd)
	if err != nil {
		result.FailReason = fmt.Sprintf("Failed to get PostgreSQL shared directory: %s, Error: %v", errStr, err)
		result.Status = "Fail"
		return result, nil
	}
	sharedDir = strings.TrimSpace(sharedDir)

	// Determine the extension directory
	extDir := fmt.Sprintf("%s/extension", sharedDir)

	// Check the permissions and ownership
	permCmd := fmt.Sprintf("sudo ls -ld %s", extDir)
	permissions, errStr, err := utils.ExecBash(permCmd)
	if err != nil {
		result.FailReason = fmt.Sprintf("Failed to check permissions for the extension directory: %s, Error: %v", errStr, err)
		result.Status = "Fail"
		return result, nil
	}
	permissions = strings.TrimSpace(permissions)

	// Expected permissions and owner (drwxr-xr-x root root)
	expectedPermissions := "drwxr-xr-x"
	expectedOwner := "root root"
	if !strings.HasPrefix(permissions, expectedPermissions) || !strings.HasSuffix(permissions, expectedOwner) {
		result.FailReason = fmt.Sprintf("Incorrect permissions or owner for the extension directory. Expected '%s %s', got '%s'", expectedPermissions, expectedOwner, permissions)
		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}

	return result, nil
}

// 2.2 EnsureExtensionDirOwnershipAndPermissions checks the permissions and ownership of the PostgreSQL extension directory. (v14)
func EnsureExtensionDirOwnershipAndPermissions_v14(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "2.2",
		Title:   "Ensure extension directory has appropriate ownership and permissions",
		Description: `The extension directory is the location of the PostgreSQL extensions,
		which are storage engines or user defined functions (UDFs).`,
		Rationale: `Limiting the accessibility of these objects will protect the confidentiality, 
		integrity, and availability of the PostgreSQL database. If someone can modify extensions, 
		then these extensions can be used to execute illicit instructions.`,
		Procedure: `Check the ownership and permissions of the PostgreSQL extension directory to ensure 
		it is owned by root with permissions 
		drwxr-xr-x.`,
		References: `CIS PostgreSQL 14
		v1.2.0 - 03-29-2024`,
	}

	// Get the PostgreSQL shared directory
	sharedDirCmd := "sudo /usr/pgsql-14/bin/pg_config --sharedir"
	sharedDir, errStr, err := utils.ExecBash(sharedDirCmd)
	if err != nil {
		result.FailReason = fmt.Sprintf("Failed to get PostgreSQL shared directory: %s, Error: %v", errStr, err)
		result.Status = "Fail"
		return result, nil
	}
	sharedDir = strings.TrimSpace(sharedDir)

	// Determine the extension directory
	extDir := fmt.Sprintf("%s/extension", sharedDir)

	// Check the permissions and ownership
	permCmd := fmt.Sprintf("sudo ls -ld %s", extDir)
	permissions, errStr, err := utils.ExecBash(permCmd)
	if err != nil {
		result.FailReason = fmt.Sprintf("Failed to check permissions for the extension directory: %s, Error: %v", errStr, err)
		result.Status = "Fail"
		return result, nil
	}
	permissions = strings.TrimSpace(permissions)

	// Expected permissions and owner (drwxr-xr-x root root)
	expectedPermissions := "drwxr-xr-x"
	expectedOwner := "root root"
	if !strings.HasPrefix(permissions, expectedPermissions) || !strings.HasSuffix(permissions, expectedOwner) {
		result.FailReason = fmt.Sprintf("Incorrect permissions or owner for the extension directory. Expected '%s %s', got '%s'", expectedPermissions, expectedOwner, permissions)
		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}

	return result, nil
}

// 2.3 CheckPostgresCommandHistory disables logging of the PostgreSQL client commands in the .psql_history file.
func CheckPostgresCommandHistory(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.3",
		Title:       "Disable PostgreSQL Command History",
		Description: "The PostgreSQL command history should be disabled to prevent sensitive information from being logged.",
		Rationale: `Disabling the PostgreSQL command history reduces the probability of exposing sensitive information, 
		such as passwords, encryption keys, or sensitive data.`,
		Procedure: "Check that all `.psql_history` files are symbolically linked to `/dev/null`.",
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Commands to find and check .psql_history files
	commands := []string{
		"sudo find /home -name \".psql_history\" -exec ls -la {} \\;",
		"sudo find /root -name \".psql_history\" -exec ls -la {} \\;",
	}

	findings := []string{}

	for _, cmd := range commands {
		output, errStr, err := utils.ExecBash(cmd)
		if err != nil {
			result.FailReason = fmt.Sprintf("Error executing command: %s, Error: %v, Stderr: %s", cmd, err, errStr)
			result.Status = "Fail"
			return result, nil
		}
		if output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			for _, line := range lines {
				if !strings.Contains(line, "-> /dev/null") {
					findings = append(findings, line)
				}
			}
		}
	}

	if len(findings) > 0 {
		result.FailReason = fmt.Sprintf("The following `.psql_history` files are not disabled: %s", strings.Join(findings, ", "))
		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}

	return result, nil
}

// 2.4 CheckPasswordsInServiceFiles checks for the presence of passwords in PostgreSQL service files.
func CheckPasswordsInServiceFiles(db *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.4",
		Title:       "Ensure Passwords are Not Stored in the Service File",
		Description: "Verify the password option is not used in a connection service file.",
		Rationale:   "Using the password parameter may negatively impact the confidentiality of the user's password.",
		Procedure:   "Scan the system for .pg_service.conf files and ensure they do not contain any password entries.",
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Define commands to search for .pg_service.conf files and check for password entries
	commands := []string{
		"sudo find / -name .pg_service.conf -type f -exec cat {} \\; 2>/dev/null | grep password",
		"sudo grep password /root/.pg_service.conf",
		// Assuming environment variables PGSERVICEFILE and PGSYSCONFDIR are set and exported in the environment
		"grep password \"$PGSERVICEFILE\"",
		"grep password \"$PGSYSCONFDIR/pg_service.conf\"",
	}

	findings := []string{}

	for _, cmd := range commands {
		output, errStr, err := utils.ExecBash(cmd)
		if err != nil {
			result.FailReason = fmt.Sprintf("Error executing command: %s, Error: %v, Stderr: %s", cmd, err, errStr)
			result.Status = "Fail"
			return result, nil
		}
		if output != "" {
			// Record each file that contains a password
			if strings.Contains(output, "password=") {
				findings = append(findings, output)
			}
		}
	}

	if len(findings) > 0 {
		result.FailReason = fmt.Sprintf("Password entries found in service files: %s", strings.Join(findings, ", "))
		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}

	return result, nil
}
