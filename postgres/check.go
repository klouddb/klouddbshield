package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres/auth"
	"github.com/klouddb/klouddbshield/postgres/connection"
	"github.com/klouddb/klouddbshield/postgres/helper"
	"github.com/klouddb/klouddbshield/postgres/installation"
	"github.com/klouddb/klouddbshield/postgres/lma"
	"github.com/klouddb/klouddbshield/postgres/permissions"
	"github.com/klouddb/klouddbshield/postgres/replication"
	"github.com/klouddb/klouddbshield/postgres/settings"
	"github.com/klouddb/klouddbshield/postgres/special"
)

var referenceMap = map[string]string{
	"13": `CIS PostgreSQL 13
	v1.2.0 - 03-29-2024`,

	"14": `CIS PostgreSQL 14
	v1.2.0 - 03-29-2024`,

	"15": `CIS PostgreSQL 15
	v1.1.0 - 11-07-2023`,

	"16": `CIS PostgreSQL 16
	v1.0.0 - 11-07-2023`,
}

var installationChecks = map[string][]helper.CheckHelper{
	"13": {
		installation.CheckSystemdServiceFiles_v13(), // 1.3
		installation.CheckDataCluster(),             // 1.4
		installation.CheckPGPasswordProfiles(),      // 1.6
		installation.CheckPGPasswordEnvVar(),        // 1.7
	},
	"14": {
		installation.CheckSystemdServiceFiles_v14(), // 1.3
		installation.CheckDataCluster(),             // 1.4
		installation.CheckPGPasswordProfiles(),      // 1.6
		installation.CheckPGPasswordEnvVar(),        // 1.7
	},
	"15": {
		installation.CheckSystemdServiceFiles_v15(), // 1.2
		installation.CheckDataCluster(),             // 1.3
	},
	"16": {
		installation.CheckSystemdServiceFiles_v16(), // 1.2
		installation.CheckDataCluster(),             // 1.3
	},
}

var permissionsChecks = map[string][]helper.CheckHelper{
	"13": {
		permissions.CheckSystemdServiceFiles(),                      // 2.1
		permissions.EnsureExtensionDirOwnershipAndPermissions_v13(), // 2.2
		permissions.CheckPostgresCommandHistory(),                   // 2.3
		// permissions.CheckPasswordsInServiceFiles(),                  // 2.4
	},
	"14": {
		permissions.CheckSystemdServiceFiles(),                      // 2.1
		permissions.EnsureExtensionDirOwnershipAndPermissions_v14(), // 2.2
		permissions.CheckPostgresCommandHistory(),                   // 2.3
		// permissions.CheckPasswordsInServiceFiles(),                  // 2.4
	},
	"15": {
		permissions.CheckSystemdServiceFiles(), // 2.1
	},
	"16": {
		permissions.CheckSystemdServiceFiles(), // 2.1
	},
}

// var lmaChecks = []helper.CheckHelper{
// 	lma.CheckLogDest(),                // 3.1.2
// 	lma.CheckLogCol(),                 // 3.1.3
// 	lma.CheckLogDir(),                 // 3.1.4
// 	lma.CheckLogFile(),                // 3.1.5
// 	lma.CheckLogFilePerm(),            // 3.1.6
// 	lma.CheckLogTrunc(),               // 3.1.7
// 	lma.CheckLogLT(),                  // 3.1.8
// 	lma.CheckLogFileSize(),            // 3.1.9
// 	lma.CheckSyslog(),                 // 3.1.10
// 	lma.CheckSyslogSuppr(),            // 3.1.11
// 	lma.CheckServLogMsgSize(),         // 3.1.12
// 	lma.CheckSyslogMsg(),              // 3.1.13
// 	lma.CheckServLogMsg(),             // 3.1.14
// 	lma.CheckSQLStat(),                // 3.1.15
// 	lma.CheckDebugPrintParse(),        // 3.1.16
// 	lma.CheckDebugPrintRewritten(),    // 3.1.17
// 	lma.CheckDebugPrintPlan(),         // 3.1.18
// 	lma.CheckDebugPrettyPrint(),       // 3.1.19
// 	lma.CheckLogConnections(),         // 3.1.20
// 	lma.CheckLogDisconnections(),      // 3.1.21
// 	lma.ChecklogErrorVerbosity(),      // 3.1.22
// 	lma.CheckLogHostname(),            // 3.1.23
// 	lma.ChecklogLinePrefix(),          // 3.1.24
// 	lma.CheckLogStatement(),           // 3.1.25
// 	lma.CheckLogTimezone(),            // 3.1.26
// 	lma.CheckSharedPreloadLibraries(), // 3.2
// }

var authChecks = map[string][]helper.CheckHelper{
	"13": {
		auth.CheckPrivilegedAccess(),         // 4.3
		auth.CheckLockoutInactiveAccounts(),  // 4.4
		auth.CheckFunctionPrivileges(),       // 4.5
		auth.CheckDMLPrivileges(),            // 4.6
		auth.CheckRLSSecurityConfiguration(), // 4.7
		auth.CheckSetUserExtension(),         // 4.8
		auth.CheckPredefinedRoles(),          // 4.9
	},
	"14": {
		auth.CheckPrivilegedAccess(),         // 4.3
		auth.CheckLockoutInactiveAccounts(),  // 4.4
		auth.CheckFunctionPrivileges(),       // 4.5
		auth.CheckDMLPrivileges(),            // 4.6
		auth.CheckRLSSecurityConfiguration(), // 4.7
		auth.CheckSetUserExtension(),         // 4.8
		auth.CheckPredefinedRoles(),          // 4.9
	},
	"15": {
		auth.CheckPrivilegedAccess(),         // 4.2
		auth.CheckFunctionPrivileges(),       // 4.3
		auth.CheckDMLPrivileges(),            // 4.4
		auth.CheckRLSSecurityConfiguration(), // 4.5
		auth.CheckSetUserExtension(),         // 4.6
		auth.CheckPredefinedRoles(),          // 4.7
	},
	"16": {
		auth.CheckPrivilegedAccess(),         // 4.2
		auth.CheckFunctionPrivileges(),       // 4.3
		auth.CheckDMLPrivileges(),            // 4.4
		auth.CheckRLSSecurityConfiguration(), // 4.5
		auth.CheckSetUserExtension(),         // 4.6
		auth.CheckPredefinedRoles(),          // 4.7
	},
}

var connectionChecks = map[string][]helper.CheckHelper{
	"13": {
		connection.CheckPasswordInCommandline(), // 5.1
		connection.CheckPostgresIPBound(),       // 5.2
		connection.CheckLocalSocketLogin(),      // 5.3
		connection.CheckHostSocketLogin(),       // 5.4
		connection.CheckConnectionLimits(),      // 5.5
		connection.CheckPasswordComplexity(),    // 5.6
	},
	"14": {
		connection.CheckPasswordInCommandline(), // 5.1
		connection.CheckPostgresIPBound(),       // 5.2
		connection.CheckLocalSocketLogin(),      // 5.3
		connection.CheckHostSocketLogin(),       // 5.4
		connection.CheckConnectionLimits(),      // 5.5
		connection.CheckPasswordComplexity(),    // 5.6
	},
	"15": {
		connection.CheckLocalSocketLogin(),   // 5.1
		connection.CheckHostSocketLogin(),    // 5.2
		connection.CheckPasswordComplexity(), // 5.3
	},
	"16": {
		connection.CheckLocalSocketLogin(),   // 5.1
		connection.CheckHostSocketLogin(),    // 5.2
		connection.CheckPasswordComplexity(), // 5.3
	},
}

var settingsChecks = map[string][]helper.CheckHelper{
	"13": {
		settings.CheckSetUserExtension(), // 6.2
		settings.CheckPostmasterParams(), // 6.3
		settings.CheckSignupParams(),     // 6.4
		settings.CheckSupperUserParams(), // 6.5
		settings.CheckUserParams(),       // 6.6
		settings.CheckFIPS(),             // 6.7
		settings.CheckSSL(),              // 6.8
		settings.CheckTLSVersions(),      // 6.9
		settings.CheckSSLCiphers(),       // 6.10
		settings.CheckPGCrypto(),         // 6.11
	},
	"14": {
		settings.CheckSetUserExtension(), // 6.2
		settings.CheckPostmasterParams(), // 6.3
		settings.CheckSignupParams(),     // 6.4
		settings.CheckSupperUserParams(), // 6.5
		settings.CheckUserParams(),       // 6.6
		settings.CheckFIPS(),             // 6.7
		settings.CheckSSL(),              // 6.8
		settings.CheckTLSVersions(),      // 6.9
		settings.CheckSSLCiphers(),       // 6.10
		settings.CheckPGCrypto(),         // 6.11
	},
	"15": {
		settings.CheckSetUserExtension(), // 6.2
		settings.CheckPostmasterParams(), // 6.3
		settings.CheckSignupParams(),     // 6.4
		settings.CheckSupperUserParams(), // 6.5
		settings.CheckUserParams(),       // 6.6
		settings.CheckFIPS(),             // 6.7
		settings.CheckSSL(),              // 6.8
		settings.CheckPGCrypto(),         // 6.9
	},
	"16": {
		settings.CheckSetUserExtension(), // 6.2
		settings.CheckPostmasterParams(), // 6.3
		settings.CheckSignupParams(),     // 6.4
		settings.CheckSupperUserParams(), // 6.5
		settings.CheckUserParams(),       // 6.6
		settings.CheckFIPS(),             // 6.7
		settings.CheckSSL(),              // 6.8
		settings.CheckPGCrypto(),         // 6.9
	},
}

var replicationChecks = map[string][]helper.CheckHelper{
	"13": {
		replication.CheckReplicationUser(),                   // 7.1
		replication.CheckReplicationLogging(),                // 7.2
		replication.CheckBaseBackupConfiguration(),           // 7.3
		replication.CheckArchiveMode(),                       // 7.4
		replication.CheckStreamingReplicationConfiguration(), // 7.5
	},
	"14": {
		replication.CheckReplicationUser(),                   // 7.1
		replication.CheckReplicationLogging(),                // 7.2
		replication.CheckBaseBackupConfiguration(),           // 7.3
		replication.CheckArchiveMode(),                       // 7.4
		replication.CheckStreamingReplicationConfiguration(), // 7.5
	},
	"15": {
		replication.CheckReplicationUser(),                   // 7.1
		replication.CheckReplicationLogging(),                // 7.2
		replication.CheckBaseBackupConfiguration(),           // 7.3
		replication.CheckArchiveMode(),                       // 7.4
		replication.CheckStreamingReplicationConfiguration(), // 7.5
	},
	"16": {
		replication.CheckReplicationUser(),                   // 7.1
		replication.CheckReplicationLogging(),                // 7.2
		replication.CheckBaseBackupConfiguration(),           // 7.3
		replication.CheckArchiveMode(),                       // 7.4
		replication.CheckStreamingReplicationConfiguration(), // 7.5
	},
}

var specialChecks = map[string][]helper.CheckHelper{
	"13": {
		special.CheckPostgresSubdirecotry(),              // 8.1
		special.CheckPgBackRestInstallation(),            // 8.2
		special.CheckMiscellaneousConfigurationSetting(), // 8.3
	},
	"14": {
		special.CheckPostgresSubdirecotry(),              // 8.1
		special.CheckPgBackRestInstallation(),            // 8.2
		special.CheckMiscellaneousConfigurationSetting(), // 8.3
	},
	"15": {
		special.CheckPostgresSubdirecotry(),              // 8.1
		special.CheckPgBackRestInstallation(),            // 8.2
		special.CheckMiscellaneousConfigurationSetting(), // 8.3
	},
	"16": {
		special.CheckPostgresSubdirecotry(),              // 8.1
		special.CheckPgBackRestInstallation(),            // 8.2
		special.CheckMiscellaneousConfigurationSetting(), // 8.3
	},
}

func createPreLMACheckList(version string) []helper.CheckHelper {
	var listOfChecks []helper.CheckHelper

	// 1.0
	if checks, ok := installationChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	// 2.0
	if checks, ok := permissionsChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	return listOfChecks
}

func createPostLMACheckList(version string) []helper.CheckHelper {
	var listOfChecks []helper.CheckHelper

	// Append checks from each category based on the version
	// 4.0
	if checks, ok := authChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	// 5.0
	if checks, ok := connectionChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	// 6.0
	if checks, ok := settingsChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	// 7.0
	if checks, ok := replicationChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}
	// 8.0
	if checks, ok := specialChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	return listOfChecks
}

func getPG_settings(postgresDB *sql.DB) map[string]string {
	rows, err := postgresDB.Query("SELECT name, setting FROM pg_settings")
	if err != nil {
		log.Print(err)
		return nil
	}
	defer rows.Close()

	// Map to hold settings
	settingsMap := make(map[string]string)

	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			log.Print("Error scanning pg_settings row")
			log.Print(err)
			return nil
		}
		settingsMap[name] = setting
	}
	return settingsMap
}

// func isLMACheck(fn checkFunc) bool {
// 	for _, f := range lmaChecks {
// 		if fmt.Sprintf("%p", f) == fmt.Sprintf("%p", fn) {
// 			return true
// 		}
// 	}
// 	return false
// }

func PerformAllChecks(store *sql.DB, ctx context.Context, version string, controlSet utils.Set[string]) ([]*model.Result, map[int]*model.Status, error) {
	var listOfResult []*model.Result
	var err error = nil

	ctx = model.NewContextWithVersion(ctx, version)

	settingsMap := getPG_settings(store)

	// version = "16"

	preLMA_checks := helper.FilterCheckHelpers(createPreLMACheckList(version), controlSet)
	postLMA_checks := helper.FilterCheckHelpers(createPostLMACheckList(version), controlSet)

	// Run pre-LMA checks
	// fmt.Println("Running pre-LMA checks...")
	for _, h := range preLMA_checks {
		result, err := h.ExecuteCheck(store, ctx)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
		}
		if result == nil {
			// log.Print("Got nil for ", function)
			continue
		}
		result.References = referenceMap[version]

		// Installation updates
		if result.Control == "1.3" && result.Title == "Ensure Data Cluster Initialized Successfully" {
			if version == "13" || version == "14" {
				result.Control = "1.4"
			}
		}

		listOfResult = append(listOfResult, result)
	}

	// Run LMA checks
	// fmt.Println("Running LMA checks...")

	// List of keys in the desired order
	keysInOrder := []string{
		"log_destination", "logging_collector", "log_directory", "log_filename",
		"log_file_mode", "log_truncate_on_rotation", "log_rotation_age", "log_rotation_size",
		"syslog_facility", "syslog_sequence_numbers", "syslog_split_messages", "syslog_ident",
		"log_min_messages", "log_min_error_statement", "debug_print_parse", "debug_print_rewritten",
		"debug_print_plan", "debug_pretty_print", "log_connections", "log_disconnections",
		"log_error_verbosity", "log_hostname", "log_line_prefix", "log_statement",
		"log_timezone", "shared_preload_libraries",
	}

	lmaResults := lma.Check_LMA_Results(settingsMap)
	for _, key := range keysInOrder {
		if result := lmaResults[key]; result != nil && controlSet.Contains(result.Control) {
			result.References = referenceMap[version]
			listOfResult = append(listOfResult, result)
		}
	}

	// Run post-LMA checks
	// fmt.Println("Running post-LMA checks...")
	for _, h := range postLMA_checks {
		result, err := h.ExecuteCheck(store, ctx)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
		}
		if result == nil {
			continue
		}

		// Update result reference and control if needed
		result.References = referenceMap[version]
		// Auth updates
		if result.Control == "4.3" {
			if version == "13" || version == "14" {
				result.Control = "4.5"
			}
		} else if result.Control == "4.6" {
			if version == "13" || version == "14" {
				result.Control = "4.8"
			}
		}
		// Settings updates
		if result.Control == "6.9" && result.Title == "Ensure the pgcrypto extension is installed and configured correctly" {
			if version == "13" || version == "14" {
				result.Control = "6.11"
			}
		}

		listOfResult = append(listOfResult, result)
	}
	score := CalculateScore(listOfResult)
	return listOfResult, score, err
}
func CalculateScore(listOfResult []*model.Result) map[int]*model.Status {

	score := make(map[int]*model.Status)
	for i := 0; i <= 8; i++ {
		score[i] = new(model.Status)
	}
	for _, result := range listOfResult {
		controlPrefix := strings.Split(result.Control, ".")[0]
		controlNum, err := strconv.Atoi(controlPrefix)
		if err != nil {
			log.Print("Error converting control prefix to int")
			log.Print(err)
			continue
		}

		if result.Status == "Pass" {
			score[controlNum].Pass += 1
			score[0].Pass += 1
		} else if result.Status == "Fail" {
			score[controlNum].Fail += 1
			score[0].Fail += 1
		}
	}

	return score
}

func CheckByControl(store *sql.DB, ctx context.Context, control string) *model.Result {

	funcStore := map[string]helper.CheckHelper{
		"1.2":    installation.CheckSystemdServiceFiles_v13(),
		"1.3":    installation.CheckDataCluster(),        // 1.3
		"2.1":    permissions.CheckSystemdServiceFiles(), // 2.1
		"3.1.2":  lma.CheckLogDest(),
		"3.1.3":  lma.CheckLogCol(),
		"3.1.4":  lma.CheckLogDir(),
		"3.1.5":  lma.CheckLogFile(),
		"3.1.6":  lma.CheckLogFilePerm(),
		"3.1.7":  lma.CheckLogTrunc(),
		"3.1.8":  lma.CheckLogLT(),
		"3.1.9":  lma.CheckLogFileSize(),
		"3.1.10": lma.CheckSyslog(),
		"3.1.11": lma.CheckSyslogMsg(),
		"3.1.12": lma.CheckServLogMsg(),
		"3.1.13": lma.CheckSQLStat(),
		"3.1.14": lma.CheckDebugPrintParse(),
		"3.1.15": lma.CheckDebugPrintRewritten(),
		"3.1.16": lma.CheckDebugPrintPlan(),
		"3.1.17": lma.CheckDebugPrettyPrint(),
		"3.1.18": lma.CheckLogConnections(),
		"3.1.19": lma.CheckLogDisconnections(),
		"3.1.20": lma.ChecklogErrorVerbosity(),
		"3.1.21": lma.CheckLogHostname(),
		"3.1.22": lma.ChecklogLinePrefix(),
		"3.1.23": lma.CheckLogStatement(),
		"3.1.24": lma.CheckLogTimezone(),
		"3.2":    lma.CheckSharedPreloadLibraries(),
		"4.3":    auth.CheckFunctionPrivileges(),
		"4.5":    auth.CheckObjectPermissions(),
		"4.7":    auth.CheckSetUserExtension(),
		"6.2":    settings.CheckSetUserExtension(),
		"6.7":    settings.CheckFIPS(),
		"6.8":    settings.CheckSSL(),
		"6.9":    settings.CheckPGCrypto(),
		"7.3":    replication.CheckArchiveMode(),
	}
	if h, ok := funcStore[control]; ok {
		result, _ := h.ExecuteCheck(store, ctx)
		return result
	}
	fmt.Println("Invalid Control, Try Again!")
	// result, _ := myFunc(store, ctx)
	return nil
}
