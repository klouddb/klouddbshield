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
		installation.CheckSystemdServiceFiles,
		installation.CheckDataCluster,
		permissions.CheckSystemdServiceFiles,
		lma.CheckLogDest,
		lma.CheckLogCol,
		lma.CheckLogDir,
		lma.CheckLogFile,
		lma.CheckLogFilePerm,
		lma.CheckLogTrunc,
		lma.CheckLogLT,
		lma.CheckLogFileSize,
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
