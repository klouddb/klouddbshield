package installation

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 1.3 Ensure systemd Service Files Are Enabled (v13)
func CheckSystemdServiceFiles_v13(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.3",
		Title:       "Ensure systemd Service Files Are Enabled",
		Description: "Confirm, and correct if necessary, the PostgreSQL systemd service is enabled",
		Rationale:   "Enabling the systemd service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.",
		Procedure: `Run below command to see if it returns any output .
		If not then it is a FAIL.
		$ systemctl is-enabled postgresql-13.service`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}
	cmd := "sudo systemctl is-enabled postgresql-13.service"

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr == "enabled" {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
		result.Status = "Fail"
	}

	return result, nil
}

// 1.3 Ensure systemd Service Files Are Enabled (v14)
func CheckSystemdServiceFiles_v14(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.3",
		Title:       "Ensure systemd Service Files Are Enabled",
		Description: "Confirm, and correct if necessary, the PostgreSQL systemd service is enabled",
		Rationale:   "Enabling the systemd service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.",
		Procedure: `Run below command to see if it returns any output .
		If not then it is a FAIL.
		$ systemctl is-enabled postgresql-14.service`,
		References: `CIS PostgreSQL 14
		v1.2.0 - 03-29-2024`,
	}
	cmd := "sudo systemctl is-enabled postgresql-14.service"

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr == "enabled" {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
		result.Status = "Fail"
	}

	return result, nil
}

// 1.2 Ensure systemd Service Files Are Enabled (v15)
func CheckSystemdServiceFiles_v15(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.2",
		Title:       "Ensure systemd Service Files Are Enabled",
		Description: "Confirm, and correct if necessary, the PostgreSQL systemd service is enabled",
		Rationale:   "Enabling the systemd service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.",
		Procedure: `Confirm the PostgreSQL service is enabled by executing the following: 
		$ systemctl is-enabled postgresql-15.service`,
		References: `CIS PostgreSQL 15
		v1.1.0 - 11-07-2023`,
	}
	cmd := "sudo systemctl is-enabled postgres-15.service"

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr == "enabled" {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
		result.Status = "Fail"
	}

	return result, nil
}

// 1.2 Ensure systemd Service Files Are Enabled (v16)
func CheckSystemdServiceFiles_v16(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.2",
		Title:       "Ensure systemd Service Files Are Enabled",
		Description: "Confirm, and correct if necessary, the PostgreSQL systemd service is enabled",
		Rationale:   "Enabling the systemd service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.",
		Procedure: `Confirm the PostgreSQL service is enabled by executing the following: 
		$ systemctl is-enabled postgresql-16.service`,
		References: `CIS PostgreSQL 16
		v1.0.0 - 11-07-2023`,
	}
	cmd := "sudo systemctl is-enabled postgres-16.service"

	outStr, errStr, err := utils.ExecBash(cmd)

	if outStr == "enabled" {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
		result.Status = "Fail"
	}

	return result, nil
}

// 1.3 Ensure Data Cluster Initialized Successfully
func CheckDataCluster(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "1.3",
		Title:   "Ensure Data Cluster Initialized Successfully",
		Description: `First-time installs of PostgreSQL require the instantiation of the database cluster.
		A database cluster is a collection of databases that are managed by a single server instance.`,
		Procedure: `# whoami
		postgres
		# /usr/pgsql-13/bin/postgresql-13-check-db-dir ~postgres/13/data
		# echo $?
		As long as the return code is zero(0), as shown, everything is fine.`,
		Rationale: `For the purposes of security, PostgreSQL enforces ownership and permissions of the data cluster such that:
		• An initialized data cluster is owned by the UNIX account that created it.
		• The data cluster cannot be accessed by other UNIX user accounts.
		• The data-cluster cannot be created or owned by root
		• The PostgreSQL process cannot be invoked by root nor any UNIX user account other than the owner of the data cluster.
		`,
		References: `CIS PostgreSQL 13 Benchmark
v1.0.0 - 02-26-2021`,
	}
	query := `SHOW server_version;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err
		return result, nil
	}

	version := ""
	ver := 1.1
	for _, obj := range data {
		if obj["server_version"] != nil {
			version = fmt.Sprint(obj["server_version"])
			break
		}
	}
	v := strings.Split(version, " ")[0]
	if s, err := strconv.ParseFloat(v, 32); err == nil {
		ver = s
	} else {
		result.Status = "Fail"
		result.FailReason = "Unable to parse version " + version + ". Error:	" + err.Error()
		return result, nil
	}
	query = `show data_directory;`

	data, err = utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err
		return result, nil
	}

	dataDirectory := ""
	for _, obj := range data {
		if obj["data_directory"] != nil {
			dataDirectory = fmt.Sprint(obj["data_directory"])
			break
		}
	}
	cmd := ""
	if ver >= 13 && ver < 14 {
		cmd = "sudo -u postgres /usr/pgsql-13/bin/postgresql-13-check-db-dir " + dataDirectory
	}
	if ver >= 14 && ver < 15 {
		cmd = "sudo -u postgres /usr/pgsql-14/bin/postgresql-14-check-db-dir " + dataDirectory
	}
	if ver >= 15 && ver < 16 {
		cmd = "sudo -u postgres /usr/pgsql-15/bin/postgresql-15-check-db-dir " + dataDirectory
	}
	if ver >= 15 && ver < 16 {
		cmd = "sudo -u postgres /usr/pgsql-16/bin/postgresql-16-check-db-dir " + dataDirectory
	}
	if ver < 13 || ver > 16 {
		result.FailReason = "The postgres version is " + version + ", which is not supported as of now."
		result.Status = "Fail"
		return result, nil
	}
	_, errStr, err := utils.ExecBash(cmd)

	if errStr != "" && err != nil {
		result.Status = "Pass"
	} else {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err, errStr)
		result.Status = "Fail"
	}

	return result, nil
}

// 1.6 Verify the 'PGPASSWORD' is Not  Set in User's Profiles
func CheckPGPasswordProfiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control: "1.6",
		Title:   "Verify That 'PGPASSWORD' is Not Set in Users' Profiles",
		Description: `PostgreSQL can read a default database password from
		an environment variable called PGPASSWORD.`,
		Rationale: `Use of the PGPASSWORD environment variable implies PostgreSQL credentials
		 are stored as clear text. Avoiding this may increase assurance that the confidentiality
		  of PostgreSQL credentials is preserved.`,
		Procedure: `To assess this recommendation, check if PGPASSWORD is set in login scripts using the 
		following terminal command as privileged user: 
		grep PGPASSWORD --no-messages /home/*/.{bashrc,profile,bash_profile} 
		grep PGPASSWORD --no-messages /root/.{bashrc,profile,bash_profile} 
		grep PGPASSWORD --no-messages /etc/environment`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Commands to check for the PGPASSWORD in user profiles and environment files
	commands := []string{
		"sudo grep PGPASSWORD --no-messages /home/*/.{bashrc,profile,bash_profile}",
		"sudo grep PGPASSWORD --no-messages /root/.{bashrc,profile,bash_profile}",
		"sudo grep PGPASSWORD --no-messages /etc/environment",
	}

	// Execute each command and check for occurrences of PGPASSWORD
	for _, cmd := range commands {
		outStr, errStr, err := utils.ExecBash(cmd)
		if err != nil {
			result.FailReason = fmt.Sprintf("Error executing command: %s, Error: %v, Stderr: %s", cmd, err, errStr)
			result.Status = "Fail"
			return result, nil
		}
		if strings.TrimSpace(outStr) != "" {
			result.FailReason = fmt.Sprintf("Found 'PGPASSWORD' set in profiles or environment files. Details: %s", outStr)
			result.Status = "Fail"
			return result, nil
		}
	}

	result.Status = "Pass"
	return result, nil
}

// 1.7 Verify That the 'PGPASSWORD' Environment Variable is Not in Use
func CheckPGPasswordEnvVar(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "1.7",
		Title:       "Verify That the 'PGPASSWORD' Environment Variable is Not in Use",
		Description: "PostgreSQL can read a default database password from an environment variable called PGPASSWORD.",
		Rationale: `Using the PGPASSWORD environment variable implies PostgreSQL 
		credentials are stored as clear text. Avoiding use of this environment variable can 
		better safeguard the confidentiality of PostgreSQL credentials.`,
		Procedure: `To assess this recommendation, use the /proc filesystem and the 
		following terminal command as privileged root user to determine if PGPASSWORD is currently set for any process: 
		sudo grep PGPASSWORD /proc/*/environ 
		This may return one false-positive entry for the process which is executing the grep command.`,
		References: `CIS PostgreSQL 13
		v1.2.0 - 03-29-2024`,
	}

	// Command to check if PGPASSWORD is set in any running process's environment
	cmd := "sudo grep PGPASSWORD /proc/*/environ --no-messages"

	outStr, errStr, err := utils.ExecBash(cmd)
	if err != nil {
		result.FailReason = fmt.Sprintf("Error executing command: %s, Error: %v, Stderr: %s", cmd, err, errStr)
		result.Status = "Fail"
		return result, nil
	}

	// Process the output to exclude the grep process itself which might show up as a false positive
	lines := strings.Split(outStr, "\n")
	validEntries := []string{}
	for _, line := range lines {
		if !strings.Contains(line, "grep") {
			validEntries = append(validEntries, line)
		}
	}

	if len(validEntries) > 0 {
		result.FailReason = fmt.Sprintf("PGPASSWORD is set in the environments of the following processes: %s", strings.Join(validEntries, ", "))
		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}

	return result, nil
}
