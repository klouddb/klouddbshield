package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/postgres/auth"
	"github.com/klouddb/klouddbshield/postgres/connection"
	"github.com/klouddb/klouddbshield/postgres/installation"
	"github.com/klouddb/klouddbshield/postgres/lma"
	"github.com/klouddb/klouddbshield/postgres/permissions"
	"github.com/klouddb/klouddbshield/postgres/replication"
	"github.com/klouddb/klouddbshield/postgres/settings"
	"github.com/klouddb/klouddbshield/postgres/special"
)

type checkFunc func(*sql.DB, context.Context) (*model.Result, error)

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

var installationChecks = map[string][]checkFunc{
	"13": {
		installation.CheckSystemdServiceFiles_v13, // 1.3
		installation.CheckDataCluster,             // 1.4
		installation.CheckPGPasswordProfiles,      // 1.6
		installation.CheckPGPasswordEnvVar,        // 1.7
	},
	"14": {
		installation.CheckSystemdServiceFiles_v14, // 1.3
		installation.CheckDataCluster,             // 1.4
		installation.CheckPGPasswordProfiles,      // 1.6
		installation.CheckPGPasswordEnvVar,        // 1.7
	},
	"15": {
		installation.CheckSystemdServiceFiles_v15, // 1.2
		installation.CheckDataCluster,             // 1.3
	},
	"16": {
		installation.CheckSystemdServiceFiles_v16, // 1.2
		installation.CheckDataCluster,             // 1.3
	},
}

var permissionsChecks = map[string][]checkFunc{
	"13": {
		permissions.CheckSystemdServiceFiles,                      // 2.1
		permissions.EnsureExtensionDirOwnershipAndPermissions_v13, // 2.2
		permissions.CheckPostgresCommandHistory,                   // 2.3
		permissions.CheckPasswordsInServiceFiles,                  // 2.4
	},
	"14": {
		permissions.CheckSystemdServiceFiles,                      // 2.1
		permissions.EnsureExtensionDirOwnershipAndPermissions_v14, // 2.2
		permissions.CheckPostgresCommandHistory,                   // 2.3
		permissions.CheckPasswordsInServiceFiles,                  // 2.4
	},
	"15": {
		permissions.CheckSystemdServiceFiles, // 2.1
	},
	"16": {
		permissions.CheckSystemdServiceFiles, // 2.1
	},
}

var lmaChecks = []checkFunc{
	lma.CheckLogDest,                // 3.1.2
	lma.CheckLogCol,                 // 3.1.3
	lma.CheckLogDir,                 // 3.1.4
	lma.CheckLogFile,                // 3.1.5
	lma.CheckLogFilePerm,            // 3.1.6
	lma.CheckLogTrunc,               // 3.1.7
	lma.CheckLogLT,                  // 3.1.8
	lma.CheckLogFileSize,            // 3.1.9
	lma.CheckSyslog,                 // 3.1.10
	lma.CheckSyslogSuppr,            // 3.1.11
	lma.CheckServLogMsgSize,         // 3.1.12
	lma.CheckSyslogMsg,              // 3.1.13
	lma.CheckServLogMsg,             // 3.1.14
	lma.CheckSQLStat,                // 3.1.15
	lma.CheckDebugPrintParse,        // 3.1.16
	lma.CheckDebugPrintRewritten,    // 3.1.17
	lma.CheckDebugPrintPlan,         // 3.1.18
	lma.CheckDebugPrettyPrint,       // 3.1.19
	lma.CheckLogConnections,         // 3.1.20
	lma.CheckLogDisconnections,      // 3.1.21
	lma.ChecklogErrorVerbosity,      // 3.1.22
	lma.CheckLogHostname,            // 3.1.23
	lma.ChecklogLinePrefix,          // 3.1.24
	lma.CheckLogStatement,           // 3.1.25
	lma.CheckLogTimezone,            // 3.1.26
	lma.CheckSharedPreloadLibraries, // 3.2
}

var authChecks = map[string][]checkFunc{
	"13": {
		auth.CheckFunctionPrivileges, // 4.5
		auth.CheckSetUserExtension,   // 4.8
	},
	"14": {
		auth.CheckFunctionPrivileges, // 4.5
		auth.CheckSetUserExtension,   // 4.8
	},
	"15": {
		auth.CheckFunctionPrivileges, // 4.3
		auth.CheckSetUserExtension,   // 4.6
	},
	"16": {
		auth.CheckFunctionPrivileges, // 4.3
		auth.CheckSetUserExtension,   // 4.6
	},
}

var connectionChecks = map[string][]checkFunc{
	"13": {
		connection.CheckConnectionLimits, // 5.5
	},
	"14": {
		connection.CheckConnectionLimits, // 5.5
	},
}

var settingsChecks = map[string][]checkFunc{
	"13": {
		settings.CheckSetUserExtension, // 6.2
		settings.CheckFIPS,             // 6.7
		settings.CheckSSL,              // 6.8
		settings.CheckTLSVersions,      // 6.9
		settings.CheckSSLCiphers,       // 6.10
		settings.CheckPGCrypto,         // 6.11
	},
	"14": {
		settings.CheckSetUserExtension, // 6.2
		settings.CheckFIPS,             // 6.7
		settings.CheckSSL,              // 6.8
		settings.CheckTLSVersions,      // 6.9
		settings.CheckSSLCiphers,       // 6.10
		settings.CheckPGCrypto,         // 6.11
	},
	"15": {
		settings.CheckSetUserExtension, // 6.2
		settings.CheckFIPS,             // 6.7
		settings.CheckSSL,              // 6.8
		settings.CheckPGCrypto,         // 6.9
	},
	"16": {
		settings.CheckSetUserExtension, // 6.2
		settings.CheckFIPS,             // 6.7
		settings.CheckSSL,              // 6.8
		settings.CheckPGCrypto,         // 6.9
	},
}

var replicationChecks = map[string][]checkFunc{
	"13": {
		replication.CheckArchiveMode, // 7.4
	},
	"14": {
		replication.CheckArchiveMode, // 7.4
	},
	"15": {
		replication.CheckArchiveMode, // 7.4
	},
	"16": {
		replication.CheckArchiveMode, // 7.4
	},
}

var specialChecks = map[string][]checkFunc{
	"13": {
		special.CheckPgBackRestInstallation, // 8.2
	},
	"14": {
		special.CheckPgBackRestInstallation, // 8.2
	},
	"15": {
		special.CheckPgBackRestInstallation, // 8.2
	},
	"16": {
		special.CheckPgBackRestInstallation, // 8.2
	},
}

func createPreLMACheckList(version string) []checkFunc {
	var listOfChecks []checkFunc

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

func createPostLMACheckList(version string) []checkFunc {
	var listOfChecks []checkFunc

	// Append checks from each category based on the version
	// 4.0
	if checks, ok := authChecks[version]; ok {
		listOfChecks = append(listOfChecks, checks...)
	}

	// 5.0
	if version == "13" || version == "14" {
		if checks, ok := connectionChecks[version]; ok {
			listOfChecks = append(listOfChecks, checks...)
		}
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

func isLMACheck(fn checkFunc) bool {
	for _, f := range lmaChecks {
		if fmt.Sprintf("%p", f) == fmt.Sprintf("%p", fn) {
			return true
		}
	}
	return false
}

func PerformAllChecks(store *sql.DB, ctx context.Context, version string) ([]*model.Result, map[int]*model.Status, error) {
	var listOfResult []*model.Result
	var err error = nil

	settingsMap := getPG_settings(store)

	// version = "16"

	preLMA_checks := createPreLMACheckList(version)
	postLMA_checks := createPostLMACheckList(version)

	// Run pre-LMA checks
	// fmt.Println("Running pre-LMA checks...")
	for _, function := range preLMA_checks {
		result, err := function(store, ctx)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
		}
		if result == nil {
			// log.Print("Got nil for ", function)
			continue
		}
		result.References = referenceMap[version]

		listOfResult = append(listOfResult, result)
	}

	// Run LMA checks
	// fmt.Println("Running LMA checks...")
	lmaResults := lma.Check_LMA_Results(settingsMap)
	for _, result := range lmaResults {
		listOfResult = append(listOfResult, result)
	}

	// Run post-LMA checks
	// fmt.Println("Running post-LMA checks...")
	for _, function := range postLMA_checks {
		result, err := function(store, ctx)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
		}
		if result == nil {
			continue
		}

		// Update result reference and control if needed
		result.References = referenceMap[version]
		// Installation updates
		if result.Control == "1.3" {
			if version == "13" || version == "14" {
				result.Control = "1.4"
			}
		}
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
	PrintScore(score)
	return listOfResult, score, err
}
func CalculateScore(listOfResult []*model.Result) map[int]*model.Status {

	score := make(map[int]*model.Status)
	for i := 0; i <= 8; i++ {
		score[i] = new(model.Status)
	}
	for _, result := range listOfResult {
		if strings.HasPrefix(result.Control, "1") {
			if result.Status == "Pass" {
				score[1].Pass += 1
				score[0].Pass += 1
			} else {
				score[1].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "2") {
			if result.Status == "Pass" {
				score[2].Pass += 1
				score[0].Pass += 1
			} else {
				score[2].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "3") {
			if result.Status == "Pass" {
				score[3].Pass += 1
				score[0].Pass += 1
			} else {
				score[3].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "4") {
			if result.Status == "Pass" {
				score[4].Pass += 1
				score[0].Pass += 1
			} else {
				score[4].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "5") {
			if result.Status == "Pass" {
				score[5].Pass += 1
				score[0].Pass += 1
			} else {
				score[5].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "6") {
			if result.Status == "Pass" {
				score[6].Pass += 1
				score[0].Pass += 1
			} else {
				score[6].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "7") {
			if result.Status == "Pass" {
				score[7].Pass += 1
				score[0].Pass += 1
			} else {
				score[7].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "8") {
			if result.Status == "Pass" {
				score[8].Pass += 1
				score[0].Pass += 1
			} else {
				score[8].Fail += 1
				score[0].Fail += 1
			}
		}

	}

	return score
}
func PrintScore(score map[int]*model.Status) {
	format := []string{
		"Section 1  - Installation and Patches              - %d/%d    - %.2f%%\n",
		"Section 2  - Directory and File Permissions        - %d/%d    - %.2f%%\n",
		"Section 3  - Logging Monitoring and Auditing       - %d/%d  - %.2f%%\n",
		"Section 4  - User Access and Authorization         - %d/%d    - %.2f%%\n",
		"Section 5  - Connection and Login                  - %d/%d    - %.2f%%\n",
		"Section 6  - Postgres Settings                     - %d/%d    - %.2f%%\n",
		"Section 7  - Replication                           - %d/%d    - %.2f%%\n",
		"Section 8  - Special Configuration Considerations  - %d/%d    - %.2f%%\n",
	}
	for key, value := range format {
		total := (score[key+1].Pass + score[key+1].Fail)
		if total == 0 {
			continue
		}
		fmt.Printf(value,
			score[key+1].Pass,
			(score[key+1].Pass + score[key+1].Fail),
			(float64(score[key+1].Pass) / float64(total) * 100),
		)
	}
	fmt.Printf("Overall Score - %d/%d - %.2f%%\n",
		score[0].Pass,
		(score[0].Pass + score[0].Fail),
		(float64(score[0].Pass) / float64((score[0].Pass + score[0].Fail)) * 100),
	)

}
func CheckByControl(store *sql.DB, ctx context.Context, control string) *model.Result {

	funcStore := map[string]func(*sql.DB, context.Context) (*model.Result, error){
		"1.2":    installation.CheckSystemdServiceFiles_v13,
		"1.3":    installation.CheckDataCluster,        // 1.3
		"2.1":    permissions.CheckSystemdServiceFiles, // 2.1
		"3.1.2":  lma.CheckLogDest,
		"3.1.3":  lma.CheckLogCol,
		"3.1.4":  lma.CheckLogDir,
		"3.1.5":  lma.CheckLogFile,
		"3.1.6":  lma.CheckLogFilePerm,
		"3.1.7":  lma.CheckLogTrunc,
		"3.1.8":  lma.CheckLogLT,
		"3.1.9":  lma.CheckLogFileSize,
		"3.1.10": lma.CheckSyslog,
		"3.1.11": lma.CheckSyslogMsg,
		"3.1.12": lma.CheckServLogMsg,
		"3.1.13": lma.CheckSQLStat,
		"3.1.14": lma.CheckDebugPrintParse,
		"3.1.15": lma.CheckDebugPrintRewritten,
		"3.1.16": lma.CheckDebugPrintPlan,
		"3.1.17": lma.CheckDebugPrettyPrint,
		"3.1.18": lma.CheckLogConnections,
		"3.1.19": lma.CheckLogDisconnections,
		"3.1.20": lma.ChecklogErrorVerbosity,
		"3.1.21": lma.CheckLogHostname,
		"3.1.22": lma.ChecklogLinePrefix,
		"3.1.23": lma.CheckLogStatement,
		"3.1.24": lma.CheckLogTimezone,
		"3.2":    lma.CheckSharedPreloadLibraries,
		"4.3":    auth.CheckFunctionPrivileges,
		"4.5":    auth.CheckObjectPermissions,
		"4.7":    auth.CheckSetUserExtension,
		"6.2":    settings.CheckSetUserExtension,
		"6.7":    settings.CheckFIPS,
		"6.8":    settings.CheckSSL,
		"6.9":    settings.CheckPGCrypto,
		"7.3":    replication.CheckArchiveMode,
	}
	if function, ok := funcStore[control]; ok {
		result, _ := function(store, ctx)
		return result
	}
	fmt.Println("Invalid Control, Try Again!")
	// result, _ := myFunc(store, ctx)
	return nil
}
