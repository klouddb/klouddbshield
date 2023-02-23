package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/klouddb/klouddbshield/model"
	auditinglogging "github.com/klouddb/klouddbshield/mysql/auditingLogging"
	"github.com/klouddb/klouddbshield/mysql/authentication"
	"github.com/klouddb/klouddbshield/mysql/filepermissions"
	"github.com/klouddb/klouddbshield/mysql/general"
	"github.com/klouddb/klouddbshield/mysql/installation"
	"github.com/klouddb/klouddbshield/mysql/network"
	"github.com/klouddb/klouddbshield/mysql/oslevelconfig"
	"github.com/klouddb/klouddbshield/mysql/replication"
)

type Status struct {
	Pass int
	Fail int
}

func PerformAllChecks(store *sql.DB, ctx context.Context) []*model.Result {
	var listOfResult []*model.Result
	// 1.1
	result, err := oslevelconfig.IsDBOnNPS(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 1.2
	result, err = oslevelconfig.LeastPrivileged(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 1.3
	result, err = oslevelconfig.CheckCommandHistory(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 1.4
	result, err = oslevelconfig.CheckMYSQLPWD(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 1.5
	result, err = oslevelconfig.CheckInteractiveLogin(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 1.6
	result, err = oslevelconfig.CheckMYSQLPWDUserProfile(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.1.5
	result, err = installation.CheckPointInTimeRec(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.2.1
	result, err = installation.CheckBinaryRelayLogs(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.7
	result, err = installation.CheckDefaultPassLt(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.8
	result, err = installation.CheckResetPassLt(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.9
	result, err = installation.CheckCurrentPassLt(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.12
	result, err = installation.CheckBlockEncryp(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.14
	result, err = installation.CheckBindAddr(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 2.15
	result, err = installation.CheckTLS(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}

	listOfResult = append(listOfResult, result)

	// 2.16
	result, err = installation.CheckClientCert(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}

	listOfResult = append(listOfResult, result)

	// 2.17
	result, err = installation.CheckSSLTLS(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}

	listOfResult = append(listOfResult, result)

	// 3.1
	result, err = filepermissions.CheckDataDirPerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		// return listOfResult
	}
	listOfResult = append(listOfResult, result)

	// 3.2
	result, err = filepermissions.CheckLogBinBasenamePerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		// return listOfResult
	}
	// log.Print(result)
	listOfResult = append(listOfResult, result)

	// 3.3
	result, err = filepermissions.CheckLogErrorPerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 3.4
	result, err = filepermissions.CheckSlowQueryLogPerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 3.5
	result, err = filepermissions.CheckRelayLogBasenamePerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 3.6
	result, err = filepermissions.CheckGeneralLogFilePerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 3.7
	result, err = filepermissions.CheckSSLKeyFilePerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 3.8
	result, err = filepermissions.CheckPluginDirPerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 3.9
	result, err = filepermissions.CheckAuditLogFilePerm(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.2
	result, err = general.CheckTestDBOnServer(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.3
	result, err = general.CheckAllowSuspiciousUdfs(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.5
	result, err = general.CheckPrefixMySqld(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.6
	result, err = general.CheckSymbolicLink(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.7
	result, err = general.CheckDaemonMemcached(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.8
	result, err = general.ChecksecureFilePriv(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 4.9
	result, err = general.CheckSQLMode(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 6.1
	result, err = auditinglogging.CheckLogError(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 6.2
	result, err = auditinglogging.CheckLogFiles(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 6.3
	result, err = auditinglogging.CheckLogErrorVerbosity(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 7.1
	result, err = authentication.CheckDefaultAuthPlugin(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 7.3
	result, err = authentication.CheckPassForAllAcc(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 7.4
	result, err = authentication.CheckDPLPassExp(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 7.5
	result, err = authentication.ChecPassComplexPolicies(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 7.6
	result, err = authentication.ChecWildcardHostnames(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 7.7
	result, err = authentication.ChecAnonymousAccounts(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 8.1
	result, err = network.CheckRequireSecureTransport(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 8.3
	result, err = network.CheckMaxConnLimits(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 9.2
	result, err = replication.CheckSOURCESSL(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)

	// 9.3
	result, err = replication.CheckMasterInfoRepo(store, ctx)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
	}
	listOfResult = append(listOfResult, result)
	CalculateScore(listOfResult)
	return listOfResult
}

func CalculateScore(listOfResult []*model.Result) map[int]*Status {

	score := make(map[int]*Status)
	score[0] = new(Status)
	score[1] = new(Status)
	score[2] = new(Status)
	score[3] = new(Status)
	score[4] = new(Status)
	score[5] = new(Status)
	score[6] = new(Status)
	score[7] = new(Status)
	score[8] = new(Status)
	score[9] = new(Status)
	score[10] = new(Status)
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
		if strings.HasPrefix(result.Control, "9") {
			if result.Status == "Pass" {
				score[9].Pass += 1
				score[0].Pass += 1
			} else {
				score[9].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "10") {
			if result.Status == "Pass" {
				score[10].Pass += 1
				score[0].Pass += 1
			} else {
				score[10].Fail += 1
				score[0].Fail += 1
			}
		}

	}
	PrintScore(score)
	return score
}
func PrintScore(score map[int]*Status) {
	format := []string{"Section 1  - Operating system          - %d/%d  - %.2f%%\n",
		"Section 2  - Installation and Planning - %d/%d - %.2f%%\n",
		"Section 3  - File Permissions          - %d/%d  - %.2f%%\n",
		"Section 4  - General                   - %d/%d  - %.2f%%\n",
		"Section 5  - MySQL Permissions         - %d/%d  - %.2f%%\n",
		"Section 6  - Auditing and Logging      - %d/%d  - %.2f%%\n",
		"Section 7  - Authentication            - %d/%d  - %.2f%%\n",
		"Section 8  - Network                   - %d/%d  - %.2f%%\n",
		"Section 9  - Replication               - %d/%d  - %.2f%%\n",
		"Section 10 - MySQL InnoDB Cluster / Group Replication - %d/%d - %.2f%%\n",
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
