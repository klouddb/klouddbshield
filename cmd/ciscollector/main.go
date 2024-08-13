package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/text"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/logger"

	"github.com/klouddb/klouddbshield/postgres"
)

func init() {
	logger.SetupLogger()
}

func main() {
	cnf := config.MustNewConfig()
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

	// if cnf.RunCrons {

	// 	// Create a new context and cancel function
	// 	ctx, cancel := context.WithCancel(context.Background())

	// 	// Create a new CronHelper instance with the context and configuration
	// 	cronHelper := NewCronHelper(ctx, cnf)

	// 	err := cronHelper.SetupCron()
	// 	if err != nil {
	// 		fmt.Println("cron setup failed: ", text.FgHiRed.Sprint(err))
	// 		return
	// 	}

	// 	cronHelper.Run(cancel)
	// 	return
	// }

	htmlReportHelper := htmlreport.NewHtmlReportHelper()

	builder := &strings.Builder{}
	defer func() {
		if builder.Len() != 0 {
			saveResultInFile(builder.String())
		}
		filePath, err := htmlReportHelper.RenderInfile("klouddbshield_report.html", 0600)
		if err != nil {
			log.Error().Err(err).Msg("Unable to generate klouddbshield_report.html file: " + err.Error())
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
		newMySqlRunner(cnf.MySQL, builder, htmlReportHelper).run(ctx) //nolint:errcheck
	}

	var postgresSummary map[int]*model.Status
	var overviewErrorMap = map[string]error{}
	var hbaResult []*model.HBAScannerResult
	if cnf.App.RunPostgres {
		postgresSummary, overviewErrorMap[cons.RootCMD_PostgresCIS] = newPostgresRunnerFromConfig(cnf.Postgres,
			builder, cnf.PostgresCheckSet, htmlReportHelper).run(ctx)
	}
	if cnf.App.HBASacanner {
		hbaResult, overviewErrorMap[cons.RootCMD_HBAScanner] = newHBARunnerFromConfig(cnf.Postgres, builder, htmlReportHelper).run(ctx)
	}

	if cnf.App.PrintSummaryOnly {
		postgres.PrintShortSummary(postgresSummary, hbaResult, overviewErrorMap)
	} else {
		postgres.PrintScore(postgresSummary)
		postgres.PrintSummary(hbaResult)
	}

	if cnf.App.RunRds {
		newRDSRunner(builder).run(ctx)
	}
	if cnf.App.VerboseHBASacanner {
		newHBARunnerByControlFromConfig(cnf).run(ctx)
	}

	if cnf.LogParser != nil {
		err := newLogParserRunnerFromConfig(cnf.Postgres, cnf.LogParser, cnf.App.Run,
			builder, htmlReportHelper).run(ctx)
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap[cons.LogParserCMD_InactiveUsr] = err
			overviewErrorMap[cons.LogParserCMD_UniqueIPs] = err
			overviewErrorMap[cons.LogParserCMD_HBAUnusedLines] = err
			overviewErrorMap[cons.LogParserCMD_PasswordLeakScanner] = err
		} else if err != nil {
			fmt.Println("> Error while running log parser: ", text.FgHiRed.Sprint(err))
		}
	} else if cnf.LogParserConfigErr != nil {
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap[cons.LogParserCMD_InactiveUsr] = cnf.LogParserConfigErr
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
			builder, htmlReportHelper).run(ctx)
	}

	if cnf.App.RunPwnedPasswords {
		newPwnedPasswordRunner(cnf.App.InputDirectory).run(ctx) //nolint:errcheck
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
		err := newPiiDbScanner(cnf.Postgres, cnf.PiiScannerConfig, htmlReportHelper).run(ctx)
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

func saveResultInFile(result string) {
	err := os.WriteFile("klouddbshield_report.txt", []byte(result), 0600)
	if err != nil {
		fmt.Println("Error while saving result in file:", text.FgHiRed.Sprint(err))
		fmt.Println("**********listOfResults*************\n", string(result))
	}
}
