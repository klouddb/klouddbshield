package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/postgres/auth"
	"github.com/klouddb/klouddbshield/postgres/installation"
	"github.com/klouddb/klouddbshield/postgres/lma"
	"github.com/klouddb/klouddbshield/postgres/permissions"
	"github.com/klouddb/klouddbshield/postgres/replication"
	"github.com/klouddb/klouddbshield/postgres/settings"
	"github.com/rs/zerolog/log"
)

func PerformAllChecks(store *sql.DB, ctx context.Context) []*model.Result {
	var listOfResult []*model.Result
	listOfChecks := []func(*sql.DB, context.Context) (*model.Result, error){
		installation.CheckSystemdServiceFiles, // 1.2
		installation.CheckDataCluster,         // 1.3
		permissions.CheckSystemdServiceFiles,  // 2.1
		lma.CheckLogDest,
		lma.CheckLogCol,
		lma.CheckLogDir,
		lma.CheckLogFile,
		lma.CheckLogFilePerm,
		lma.CheckLogTrunc,
		lma.CheckLogLT,
		lma.CheckLogFileSize,
		lma.CheckSyslog,
		lma.CheckSyslogMsg,
		lma.CheckServLogMsg,
		lma.CheckSQLStat,
		lma.CheckDebugPrintParse,
		lma.CheckDebugPrintRewritten,
		lma.CheckDebugPrintPlan,
		lma.CheckDebugPrettyPrint,
		lma.CheckLogConnections,
		lma.CheckLogDisconnections,
		lma.ChecklogErrorVerbosity,
		lma.CheckLogHostname,
		lma.ChecklogLinePrefix,
		lma.CheckLogStatement,
		lma.CheckLogTimezone,
		lma.CheckSharedPreloadLibraries,
		auth.CheckFunctionPrivileges,
		auth.CheckObjectPermissions,
		auth.CheckSetUserExtension,
		settings.CheckSetUserExtension,
		settings.CheckFIPS,
		settings.CheckSSL,
		settings.CheckPGCrypto,
		replication.CheckArchiveMode,
	}

	for _, function := range listOfChecks {
		result, err := function(store, ctx)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
		}
		if result == nil {
			// log.Print("Got nil for ", function)
			continue
		}
		listOfResult = append(listOfResult, result)
	}
	score := CalculateScore(listOfResult)
	PrintScore(score)
	return listOfResult
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
		"1.2":    installation.CheckSystemdServiceFiles,
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
