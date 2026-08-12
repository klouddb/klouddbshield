package main

import (
	"context"
	"encoding/json"
	"fmt"

	// "net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/text"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	// "github.com/rs/zerolog"
	// "github.com/rs/zerolog/log"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/logger"
	"github.com/klouddb/klouddbshield/pkg/mainserverclient"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/klouddb/klouddbshield/postgresconfig"
	// "github.com/klouddb/klouddbshiled/cmd/main-server/main"
	// "github.com/klouddb/klouddbshield/pkg/config/config.go"
)

func init() {
	logger.SetupLogger()
}

// Doc v2: Agent/node flow disabled (RUDR108). Active entrypoint: manual + cron main() below.
// func main() {
//     cnf := config.MustNewConfig()
//	nodeCfg,err := generateNodeConfigFile()
//	if err!=nil{
//		fmt.Println("Error in config file reading : ", err)
//		return
//	}
//	logger.SetupLogger()
//    ctx, cancel := context.WithCancel(context.Background())
//	state := NewAgentState()
//	results := make(chan CollectorResult, 32)
//	jobs := make(chan Job, 16)
//	go RunStateUpdater(ctx, state, results)
//	go StartJobPoller(ctx,cnf,nodeCfg,jobs)
//	go StartJobScheduler(ctx,cnf,nodeCfg,jobs)
//    go StartAgent(ctx, cnf,nodeCfg,state,results)
//	if cnf.RunCrons {
//        cronHelper := NewCronHelper(ctx, cnf)
//        if err := cronHelper.SetupCron(); err != nil {
//            fmt.Println("cron setup failed")
//        }
//        cronHelper.Run(cancel)
//    }
//    fmt.Println("agent started, waiting for shutdown")
//    waitForShutdown(cancel)
//    fmt.Println("agent stopped")
// }

// Doc v2 §4 Cron + §5 Manual (no agent/node).
func main() {
	cnf := config.MustNewConfig()

	if cnf.CheckMainServer {
		os.Exit(runMainServerConnectionCheck(cnf))
	}

	logger.SetupLogger()
	// Setup log level
	if !cnf.App.Debug {
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	}

	if cnf.App.PrintProcessTime {
		start := time.Now()
		defer func() {
			fmt.Println("Process time: ", time.Since(start))
		}()
	}

	if cnf.RunCrons {

		// Create a new context and cancel function
		ctx, cancel := context.WithCancel(context.Background())

		// Create a new CronHelper instance with the context and configuration
		cronHelper := NewCronHelper(ctx, cnf)

		if err := cronHelper.SetupCron(); err != nil {
			fmt.Println("cron setup failed: ", text.FgHiRed.Sprint(err))
			return
		}

		cronHelper.Run(cancel)
		return
	}

	htmlReportHelper := htmlreport.NewHtmlReportHelper()

	fileData := map[string]interface{}{}
	runStarted := time.Now().UTC()
	manualPushed := false
	defer func() {
		finishedAt := time.Now().UTC()
		if cnf.MainServer.Enabled && len(fileData) > 0 && !manualPushed {
			if pg := cnf.FirstPostgres(); pg != nil {
				if client, err := mainserverclient.New(cnf); err == nil {
					pushMainServerTickResults(cnf, client, fileData, runStarted, finishedAt, pg, "manual", nil, "")
				}
			}
		}
		if len(fileData) > 0 {
			saveResultInFile(fileData, cnf.OutputType)
		}
		filePath, err := htmlReportHelper.RenderInfile("klouddbshield_report.html", 0600)
		if err != nil {
			fmt.Println("Unable to generate klouddbshield_report.html file: " + err.Error())
		} else if filePath != "" {
			fmt.Println("For Detailed report please open HTML report in your browser [" + filePath + "]")
		}
	}()

	if cnf.App.PrintSummaryOnly {
		fmt.Println("Processing all checks...\r")
	}
	// Program context
	ctx := context.Background()
	if cnf.App.VerbosePostgres {
		newPostgresByControlRunnerFromConfig(cnf).run(ctx) //nolint:errcheck
		return
	}
	if cnf.App.RunMySql {
		newMySqlRunner(cnf.MySQL, fileData, htmlReportHelper, cnf.OutputType).run(ctx) //nolint:errcheck
	}

	var postgresSummary map[int]*model.Status
	overviewErrorMap := map[string]error{}
	var hbaResult []*model.HBAScannerResult
	if cnf.App.RunPostgres {
		for _, pg := range cnf.PostgresTargets() {
			targetData := map[string]interface{}{}
			summary, err := newPostgresRunnerFromConfig(pg, targetData,
				cnf.PostgresCheckSet, htmlReportHelper, cnf.OutputType).run(ctx)
			postgresSummary = summary
			overviewErrorMap[cons.RootCMD_PostgresCIS] = err
			for k, v := range targetData {
				fileData[k] = v
			}
			if cnf.MainServer.Enabled && len(targetData) > 0 {
				if client, cErr := mainserverclient.New(cnf); cErr == nil {
					runErr := ""
					if err != nil {
						runErr = err.Error()
					}
					pushMainServerTickResults(cnf, client, targetData, runStarted, time.Now().UTC(),
						pg, "manual", []string{cons.RootCMD_PostgresCIS}, runErr)
					manualPushed = true
				}
			}
		}
	}
	if cnf.App.HBASacanner {
		for _, pg := range cnf.PostgresTargets() {
			targetData := map[string]interface{}{}
			result, err := newHBARunnerFromConfig(pg, targetData, htmlReportHelper, cnf.OutputType).run(ctx)
			hbaResult = result
			overviewErrorMap[cons.RootCMD_HBAScanner] = err
			for k, v := range targetData {
				fileData[k] = v
			}
			if cnf.MainServer.Enabled && len(targetData) > 0 {
				if client, cErr := mainserverclient.New(cnf); cErr == nil {
					runErr := ""
					if err != nil {
						runErr = err.Error()
					}
					pushMainServerTickResults(cnf, client, targetData, runStarted, time.Now().UTC(),
						pg, "manual", []string{cons.RootCMD_HBAScanner}, runErr)
					manualPushed = true
				}
			}
		}
	}

	if cnf.App.PrintSummaryOnly {
		postgres.PrintShortSummary(postgresSummary, hbaResult, overviewErrorMap)
	} else {
		postgres.PrintScore(postgresSummary)
		postgres.PrintSummary(hbaResult)
	}

	if cnf.App.RunRds {
		newRDSRunner(cnf.OutputType, fileData, "RDS Report").run(ctx)
	}
	if cnf.App.VerboseHBASacanner {
		newHBARunnerByControlFromConfig(cnf).run(ctx)
	}

	if cnf.LogParser != nil {
		err := newLogParserRunnerFromConfig(cnf.Postgres, cnf.LogParser, cnf.App.Run,
			fileData, htmlReportHelper, cnf.OutputType).run(ctx)
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap[cons.LogParserCMD_InactiveUser] = err
			overviewErrorMap[cons.LogParserCMD_UniqueIPs] = err
			overviewErrorMap[cons.LogParserCMD_HBAUnusedLines] = err
			overviewErrorMap[cons.LogParserCMD_PasswordLeakScanner] = err
		} else if err != nil {
			fmt.Println("> Error while running log parser: ", text.FgHiRed.Sprint(err))
		}
	} else if cnf.LogParserConfigErr != nil {
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap[cons.LogParserCMD_InactiveUser] = cnf.LogParserConfigErr
			overviewErrorMap[cons.LogParserCMD_UniqueIPs] = cnf.LogParserConfigErr
			overviewErrorMap[cons.LogParserCMD_HBAUnusedLines] = cnf.LogParserConfigErr
			overviewErrorMap[cons.LogParserCMD_PasswordLeakScanner] = cnf.LogParserConfigErr
		} else {
			fmt.Println("> Error while parsing log parser configuration: ", text.FgHiRed.Sprint(cnf.LogParserConfigErr))
			return
		}
	}

	if cnf.App.RunPostgresConnTest {
		newPostgresPasswordScanner(cnf.Postgres).run(ctx) //nolint:errcheck
	}

	if cnf.App.RunGeneratePassword {
		newPwnedPasswordGenerator(cnf.GeneratePassword).run(ctx) //nolint:errcheck
	}

	if cnf.App.RunGenerateEncryptedPassword {
		newEncryptedPasswordGenerator().run(ctx) //nolint:errcheck
	}

	if cnf.App.RunPwnedUsers {
		overviewErrorMap[cons.RootCMD_PasswordManager] = newPwnedUserRunner(cnf.Postgres, cnf.App.Run,
			fileData, htmlReportHelper, cnf.OutputType).run(ctx)
	}

	if cnf.App.RunPwnedPasswords {
		newPwnedPasswordRunner(cnf.App.InputDirectory).run(ctx) //nolint:errcheck
	}

	if len(cnf.CompareConfig) > 0 {
		overviewErrorMap[cons.RootCMD_CompareConfig] = newCompareConfigRunner(cnf.CompareConfigBaseServer, cnf.CompareConfig, htmlReportHelper).run(ctx)
	}

	if cnf.App.TransactionWraparound {
		err := newCalTransactionRunner(cnf.Postgres, htmlReportHelper, cnf.App.PrintSummaryOnly).run(ctx)
		if err != nil {
			fmt.Println("> Error while running transaction calculator: ", text.FgHiRed.Sprint(err))
		}
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap[cons.RootCMD_TransactionWraparound] = err
		}
	}

	if cnf.PiiScannerConfig != nil {
		err := newPiiDbScanner(cnf.Postgres, cnf.PiiScannerConfig, htmlReportHelper, cnf).run(ctx)
		if err != nil {
			fmt.Println("Error while running PII Scanner: ", text.FgHiRed.Sprint(err))

			if strings.Contains(err.Error(), "Failed to import required libraries") {
				// If the error message is "Failed to import required libraries"
				// then we need to print terminal commands to install the spacy
				// libraries.
				fmt.Println(cons.MSG_SpacyInstallCommands)
			}
		}
	}

	if cnf.BackupHistoryInput.BackupTool != "" {
		overviewErrorMap[cons.RootCMD_BackupAuditTool] = newBackupHistory(cnf.BackupHistoryInput, htmlReportHelper).run(ctx)
	}

	if cnf.BackupCompliance.Enabled {
		targets := cnf.BackupComplianceTargets()
		if len(targets) == 0 {
			overviewErrorMap[cons.RootCMD_BackupCompliance] = fmt.Errorf(cons.Err_BackupCompliance_PostgresRequired)
			fmt.Println("> Error while running backup compliance: ", text.FgHiRed.Sprint(overviewErrorMap[cons.RootCMD_BackupCompliance]))
		} else {
			var firstErr error
			for _, p := range targets {
				if err := newBackupComplianceRunner(p, cnf).run(ctx, "manual"); err != nil {
					fmt.Println("> Error while running backup compliance: ", text.FgHiRed.Sprint(err))
					if firstErr == nil {
						firstErr = err
					}
				}
			}
			overviewErrorMap[cons.RootCMD_BackupCompliance] = firstErr
		}
	}

	if cnf.CreatePostgresConfig {
		overviewErrorMap[cons.RootCMD_CreatePostgresConfig] = postgresconfig.NewProcessor(".").Run(context.TODO())
		if overviewErrorMap[cons.RootCMD_CreatePostgresConfig] != nil {
			fmt.Println("> Error while generating postgresql.conf file: ", text.FgHiRed.Sprint(overviewErrorMap[cons.RootCMD_CreatePostgresConfig]))
		}
	}

	if cnf.ConfigAudit {
		overviewErrorMap[cons.RootCMD_ConfigAuditing] = newConfigAuditor(cnf.Postgres, htmlReportHelper).run(ctx)
	}

	if cnf.SSLCheck {
		overviewErrorMap[cons.RootCMD_SSLCheck] = newSslAuditor(cnf.Postgres, fileData, htmlReportHelper, cnf.OutputType).run(ctx)
	}

	if cnf.App.PrintSummaryOnly {
		htmlReportHelper.CreateAllTab()
	}

	for _, cmd := range cons.CommandList {
		v, ok := overviewErrorMap[cmd.CMD]
		if !ok {
			continue
		}
		tick := text.FgGreen.Sprint("✔")
		err := ""
		if v != nil {
			tick = text.FgHiRed.Sprint("✘")
			err = v.Error()
		}

		fmt.Println(tick, text.Bold.Sprint(cmd.Title), err)
	}
}

// func runQueryParser(ctx context.Context, cnf *config.Config) {

// 	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)

// 	queryParser := parselog.NewQueryParser(cnf, baseParser)

// 	if err := queryParser.Init(); err != nil {
// 		fmt.Println("Got error while initializing query parser:", err)
// 		return
// 	}

// 	runner.RunFastParser(ctx, cnf, queryParser.Feed, parselog.GetBaseParserValidator(baseParser))

// 	if ctx.Err() != nil {
// 		fmt.Println("file parsing is taking longer then expected, please check the file or errors in" + logger.GetLogFileName())
// 		return
// 	}

// 	fmt.Println("PII data found in the query log file")
// 	for label, v := range queryParser.GetPII() {
// 		fmt.Println("label: ", label)
// 		for _, queryData := range v {
// 			fmt.Println("\t Column:", queryData.Col, "\t Value:", queryData.Val)
// 		}
// 	}

// 	fmt.Println("Successfully parsed the query log file")
// }

// func runMismatchIPsLogParser(ctx context.Context, cnf *config.Config) {

// 	// check if postgres setting contains required variable or connection logs
// 	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%h") && !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%r") && !cnf.LogParser.PgSettings.LogConnections {
// 		fmt.Println("Please set log_line_prefix to '%h' or '%r' or enable log_connections")
// 		return
// 	}

// 	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)

// 	uniqueIPparser := parselog.NewUniqueIPParser(cnf, baseParser)

// 	runner.RunFastParser(ctx, cnf, uniqueIPparser.Feed, parselog.GetBaseParserValidator(baseParser))

// 	if ctx.Err() != nil {
// 		fmt.Println("file parsing is taking longer then expected, please check the file or errors in " + logger.GetLogFileName())
// 		return
// 	}

// 	if len(uniqueIPparser.GetUniqueIPs()) == 0 {
// 		fmt.Println("\nNo unique IPs found in the file please check the file or errors in " + logger.GetLogFileName())
// 		return
// 	}

// 	err := printMisMatchIPs(cnf.LogParser.OutputType, cnf.LogParser.IpFilePath, uniqueIPparser.GetUniqueIPs())
// 	if err != nil {
// 		fmt.Println("Got error while matching IPs from the file:", err)
// 	}

// }

// func printMisMatchIPs(outputType, filePath string, uniqueIPs map[string]bool) error {

// 	readFile, err := os.Open(filePath)
// 	if err != nil {
// 		return fmt.Errorf("error while opening file (%s): %v", filePath, err)
// 	}
// 	defer readFile.Close()

// 	fileScanner := bufio.NewScanner(readFile)
// 	mismatchIps := []string{}

// 	for fileScanner.Scan() {
// 		_, ok := uniqueIPs[fileScanner.Text()]
// 		if !ok {
// 			mismatchIps = append(mismatchIps, fileScanner.Text())
// 		}
// 	}

// 	if len(mismatchIps) == 0 {
// 		fmt.Println("\nNo mismatch IPs found")
// 		return nil
// 	}

// 	fmt.Println("\nMismatch IPs:")
// 	if outputType == "json" {
// 		// print mismatch ips in json format
// 		out, _ := json.MarshalIndent(mismatchIps, "", "\t")
// 		fmt.Println(string(out))
// 		return nil
// 	}

// 	for _, ip := range mismatchIps {
// 		fmt.Println("\t" + ip)
// 	}

// 	return nil
// }

func saveResultInFile(data map[string]interface{}, outputType string) {
	if outputType == "json" {
		result, err := json.MarshalIndent(data, "", "\t")
		if err != nil {
			fmt.Println("Error while converting data to json:", text.FgHiRed.Sprint(err))
		}

		err = os.WriteFile("klouddbshield_report.json", result, 0600)
		if err != nil {
			fmt.Println("Error while saving result in file:", text.FgHiRed.Sprint(err))
			fmt.Println("**********listOfResults*************\n", string(result))
		}
		return
	}

	builder := &strings.Builder{}
	for k, v := range data {
		builder.WriteString(k + ":\n")
		builder.WriteString(fmt.Sprintf("%v\n", v))
	}

	result := builder.String()
	err := os.WriteFile("klouddbshield_report.txt", []byte(result), 0600)
	if err != nil {
		fmt.Println("Error while saving result in file:", text.FgHiRed.Sprint(err))
		fmt.Println("**********listOfResults*************\n", string(result))
	}
}
