package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/text"
	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/logparser"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/runner"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type logParserRunner struct {
	postgresConfig   *postgresdb.Postgres
	fileData         map[string]interface{}
	logParserCnf     *config.LogParser
	isRunCmd         bool
	htmlReportHelper *htmlreport.HtmlReportHelper
	outputType       string
}

func newLogParserRunnerFromConfig(postgresConfig *postgresdb.Postgres, logParserCnf *config.LogParser, isRunCmd bool,
	fileData map[string]interface{}, htmlReportHelper *htmlreport.HtmlReportHelper, outputType string) *logParserRunner {
	return &logParserRunner{
		postgresConfig:   postgresConfig,
		fileData:         fileData,
		logParserCnf:     logParserCnf,
		isRunCmd:         isRunCmd,
		htmlReportHelper: htmlReportHelper,
		outputType:       outputType,
	}
}

func (l *logParserRunner) cronProcess(ctx context.Context) error {
	return l.run(ctx)
}

func (l *logParserRunner) run(ctx context.Context) error {

	var store *sql.DB
	if l.postgresConfig != nil {
		store, _, _ = postgresdb.Open(*l.postgresConfig)
		if store != nil {
			defer store.Close()
		}
	}
	updatePgSettings(ctx, store, l.logParserCnf.PgSettings)
	return runLogParserWithMultipleParser(ctx, l.isRunCmd, l.logParserCnf, store, l.htmlReportHelper, l.fileData, l.outputType)
}

func updatePgSettings(ctx context.Context, store *sql.DB, pgSettings *model.PgSettings) {
	if store == nil {
		return
	}
	ps, err := utils.GetPGSettings(ctx, store)
	if err != nil {
		fmt.Println("Error while getting postgres settings: ", text.FgHiRed.Sprint(err))
		os.Exit(1)
	}

	pgSettings.LogConnections = ps.LogConnections
}

func runLogParserWithMultipleParser(ctx context.Context, runCmd bool, logParserCnf *config.LogParser,
	store *sql.DB, htmlReportHelper *htmlreport.HtmlReportHelper, fileData map[string]interface{}, outputType string) error {

	allParser, err := getAllParser(ctx, logParserCnf, store)
	if err != nil {
		return fmt.Errorf("Error while getting all parser: %v", err)
	}

	runnerFunctions := []runner.ParserFunc{}
	for _, parser := range allParser {
		runnerFunctions = append(runnerFunctions, parser.Feed)
	}

	baseParser := parselog.GetDynamicBaseParser(logParserCnf.PgSettings.LogLinePrefix)

	fastRunnerResp, err := runner.RunFastParser(ctx, runCmd, baseParser, logParserCnf, runnerFunctions)
	if err != nil {
		return fmt.Errorf("Error while running fast parser: %v", err)
	}

	fmt.Println(text.Bold.Sprint("Log Parser Summary:"))
	if fastRunnerResp == nil || fastRunnerResp.TotalLines == 0 {
		logparser.PrintFileParsingError(fastRunnerResp.FileErrors)
		htmlReportHelper.RanderLogParserError(fmt.Errorf("We were not able parse any log line. Please check your log file and log line prefix."))
		return fmt.Errorf("We were not able parse any log line. Please check your log file and log line prefix.")
	}

	for _, parser := range allParser {
		if resultCalculator, ok := parser.(logparser.ResultCalculator); ok {
			err := resultCalculator.CalculateResult(ctx)
			if err != nil {
				logparser.PrintErrorBox("Error", fmt.Errorf("Error while calculating result: %v", err))
			}
		}
	}

	if runCmd {
		logparser.PrintSummary(ctx, allParser, logParserCnf, fastRunnerResp, fileData, outputType)
	} else {
		logparser.PrintFastRunnerReport(logParserCnf, fastRunnerResp)
		logparser.PrintTerminalResultsForLogParser(ctx, allParser, outputType)
	}

	htmlReportHelper.RenderLogparserResponse(ctx, allParser)
	return nil
}

func getAllParser(ctx context.Context, logParserCnf *config.LogParser, store *sql.DB) ([]runner.Parser, error) {
	allParser := []runner.Parser{}

	for _, command := range logParserCnf.Commands {
		switch command {
		case cons.LogParserCMD_HBAUnusedLines:
			unusedLinesHelper := logparser.NewUnusedHBALineHelper(store)
			err := unusedLinesHelper.Init(ctx, logParserCnf)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, unusedLinesHelper)
			}

		case cons.LogParserCMD_UniqueIPs:
			uniqueIPs := logparser.NewUniqueIPHelper()
			err := uniqueIPs.Init(ctx, logParserCnf)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, uniqueIPs)
			}
		case cons.LogParserCMD_InactiveUser:
			inactiveUser := logparser.NewInactiveUsersHelper(store)
			err := inactiveUser.Init(ctx, logParserCnf)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, inactiveUser)
			}
		case cons.LogParserCMD_PasswordLeakScanner:
			passwordLeakScanner := logparser.NewPasswordLeakHelper()
			err := passwordLeakScanner.Init(ctx, logParserCnf)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, passwordLeakScanner)
			}
		case cons.LogParserCMD_SqlInjectionScan:
			sqlInjectionScan := logparser.NewSQLInjectionHelper()
			err := sqlInjectionScan.Init(ctx, logParserCnf)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, sqlInjectionScan)
			}
		default:
			return nil, fmt.Errorf("Invalid command: %s", command)
		}
	}

	if len(allParser) == 0 {
		return nil, fmt.Errorf("No parser found for given input")
	}

	return allParser, nil
}

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
