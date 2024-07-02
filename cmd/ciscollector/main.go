package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/passwordmanager"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/logger"
	"github.com/klouddb/klouddbshield/pkg/logparser"
	"github.com/klouddb/klouddbshield/pkg/mysqldb"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/runner"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/klouddb/klouddbshield/postgres/hbascanner"
	"github.com/klouddb/klouddbshield/postgres/userlist"
	"github.com/klouddb/klouddbshield/rds"
	"github.com/klouddb/klouddbshield/simpletextreport"
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

	fileData := ""
	defer func() {
		if len(fileData) != 0 {
			saveResultInFile(fileData)
		}
		filePath, err := htmlreport.Render("klouddbshield_report.html", 0600)
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
		runPostgresByControl(ctx, cnf)
		return
	}
	if cnf.App.RunMySql {
		runMySql(ctx, cnf, &fileData)
	}

	var postgresSummary map[int]*model.Status
	var overviewErrorMap = map[string]error{}
	var hbaResult []*model.HBAScannerResult
	if cnf.App.RunPostgres {
		postgresSummary, overviewErrorMap["All Postgres checks(Recommended)"] = runPostgres(ctx, cnf, &fileData)
	}
	if cnf.App.HBASacanner {
		hbaResult, overviewErrorMap["HBA Scanner"] = runHBAScanner(ctx, cnf, &fileData)
	}

	if cnf.App.PrintSummaryOnly {
		postgres.PrintShortSummary(postgresSummary, hbaResult, overviewErrorMap)
	} else {
		postgres.PrintScore(postgresSummary)
		postgres.PrintSummary(hbaResult)
	}

	if cnf.App.RunRds {
		runRDS(ctx, cnf, &fileData)
	}
	if cnf.App.VerboseHBASacanner {
		runHBAScannerByControl(ctx, cnf)
	}

	if cnf.LogParser != nil {
		// run log parser
		// controlling number of cores used by log parser to user input value
		if cnf.LogParser.CPULimit != 0 {
			runtime.GOMAXPROCS(cnf.LogParser.CPULimit)
		}

		var store *sql.DB
		if cnf.Postgres != nil {
			store, _, _ = postgresdb.Open(*cnf.Postgres)
		}
		updatePgSettings(ctx, store, cnf.LogParser.PgSettings)
		err := runLogParserWithMultipleParser(ctx, cnf, store, &fileData)
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap["Inactive user report"] = err
			overviewErrorMap["Client ip report"] = err
			overviewErrorMap["HBA unused lines report"] = err
			overviewErrorMap["Password leak scanner"] = err
		} else if err != nil {
			fmt.Println("> Error while running log parser: ", text.FgRed.Sprint(err))
		}
	} else if cnf.LogParserConfigErr != nil {
		if cnf.App.PrintSummaryOnly {
			overviewErrorMap["Inactive user report"] = cnf.LogParserConfigErr
			overviewErrorMap["Client ip report"] = cnf.LogParserConfigErr
			overviewErrorMap["HBA unused lines report"] = cnf.LogParserConfigErr
			overviewErrorMap["Password leak scanner"] = cnf.LogParserConfigErr
		}
	}

	if cnf.App.RunPostgresConnTest {
		runPostgresPasswordScanner(ctx, cnf)
	}

	if cnf.App.RunGeneratePassword {
		runPasswordGenerator(ctx, cnf)
	}

	if cnf.App.RunGenerateEncryptedPassword {
		runEncryptedPasswordGenerator(ctx, cnf)
	}

	if cnf.App.RunPwnedUsers {
		overviewErrorMap["Password Manager"] = runPwnedUsers(ctx, cnf, &fileData)
	}

	if cnf.App.RunPwnedPasswords {
		runPwnedPassword(ctx, cnf)
	}

	if cnf.App.PrintSummaryOnly {
		htmlreport.CreateAllTab()
	}

	for _, cmd := range cons.CommandList {
		v, ok := overviewErrorMap[cmd]
		if !ok {
			continue
		}
		tick := text.FgGreen.Sprint("✔")
		err := ""
		if v != nil {
			tick = text.FgRed.Sprint("✘")
			err = v.Error()
		}

		fmt.Println(tick, cmd, err)
	}

}

func updatePgSettings(ctx context.Context, store *sql.DB, pgSettings *model.PgSettings) {
	if store == nil {
		return
	}
	ps, err := utils.GetPGSettings(ctx, store)
	if err != nil {
		fmt.Println("Error while getting postgres settings: ", text.FgRed.Sprint(err))
		os.Exit(1)
	}

	pgSettings.LogConnections = ps.LogConnections
}

func runLogParserWithMultipleParser(ctx context.Context, cnf *config.Config, store *sql.DB, fileData *string) error {
	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)
	allParser, err := getAllParser(ctx, cnf, store, baseParser)
	if err != nil {
		return fmt.Errorf("Error while getting all parser: %v", err)
	}

	validatorFunc := parselog.GetBaseParserValidator(baseParser)
	runnerFunctions := []runner.ParserFunc{}
	for _, parser := range allParser {
		runnerFunctions = append(runnerFunctions, parser.Feed)
	}

	fastRunnerResp, err := runner.RunFastParser(ctx, cnf, runnerFunctions, validatorFunc)
	if err != nil {
		return fmt.Errorf("Error while running fast parser: %v", err)
	}

	fmt.Println(text.Bold.Sprint("Log Parser Summary:"))
	if fastRunnerResp == nil || fastRunnerResp.TotalLines == 0 {
		logparser.PrintFileParsingError(fastRunnerResp.FileErrors)
		htmlreport.RanderLogParserError(fmt.Errorf("We were not able parse any log line. Please check your log file and log line prefix."))
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

	if cnf.App.PrintSummaryOnly {
		logparser.PrintSummary(ctx, allParser, cnf, fastRunnerResp, fileData)
	} else {
		logparser.PrintFastRunnerReport(cnf, fastRunnerResp)
		logparser.PrintTerminalResultsForLogParser(ctx, allParser, cnf.LogParser.OutputType)
	}

	htmlreport.RenderLogparserResponse(ctx, store, allParser)
	return nil
}

func getAllParser(ctx context.Context, cnf *config.Config, store *sql.DB, baseParser parselog.BaseParser) ([]runner.Parser, error) {
	allParser := []runner.Parser{}

	for _, command := range cnf.LogParser.Commands {
		switch command {
		case cons.LogParserCMD_HBAUnusedLines:
			unusedLinesHelper := logparser.NewUnusedHBALineHelper(store)
			err := unusedLinesHelper.Init(ctx, cnf, baseParser)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, unusedLinesHelper)
			}

		case cons.LogParserCMD_UniqueIPs:
			uniqueIPs := logparser.NewUniqueIPHelper()
			err := uniqueIPs.Init(ctx, cnf, baseParser)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, uniqueIPs)
			}
		case cons.LogParserCMD_InactiveUsr:
			inactiveUser := logparser.NewInactiveUsersHelper(store)
			err := inactiveUser.Init(ctx, cnf, baseParser)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, inactiveUser)
			}
		case cons.LogParserCMD_PasswordLeakScanner:
			passwordLeakScanner := logparser.NewPasswordLeakHelper()
			err := passwordLeakScanner.Init(ctx, cnf, baseParser)
			if err != nil {
				allParser = append(allParser, logparser.NewErrorHelper(command, "warning", err.Error()))
			} else {
				allParser = append(allParser, passwordLeakScanner)
			}
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

func saveResultInFile(result string) {
	err := os.WriteFile("klouddbshield_report.txt", []byte(result), 0600)
	if err != nil {
		fmt.Println("Error while saving result in file:", text.FgRed.Sprint(err))
		fmt.Println("**********listOfResults*************\n", string(result))
	}
}

func runPostgresByControl(ctx context.Context, cnf *config.Config) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return
	}
	result := postgres.CheckByControl(postgresStore, ctx, cnf.App.Control)
	if result == nil {
		os.Exit(1)
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if result.Status == "Pass" {
		t.AppendSeparator()
		color := text.FgGreen
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})

	} else {
		t.AppendSeparator()
		color := text.FgRed
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})
		t.AppendSeparator()
		t.AppendRow(table.Row{"Fail Reason", result.FailReason})

	}
	t.AppendSeparator()
	t.AppendRow(table.Row{"Rationale", result.Rationale})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Title", result.Title})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Procedure", result.Procedure})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Control", result.Control})
	t.AppendSeparator()
	t.AppendRow(table.Row{"References", result.References})
	t.SetStyle(table.StyleLight)
	t.Render()
}
func runMySql(ctx context.Context, cnf *config.Config, fileData *string) {
	mysqlDatabase := cnf.MySQL
	mysqlStore, _, err := mysqldb.Open(*mysqlDatabase)
	if err != nil {
		return
	}
	result := mysql.PerformAllChecks(mysqlStore, ctx)
	*fileData += simpletextreport.PrintReportInFile(result, "", "MySQL Report")
}
func runPostgres(ctx context.Context, cnf *config.Config, resultPrintData *string) (map[int]*model.Status, error) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return nil, err
	}

	// Determine Postgres version
	var postgresVersion string
	err = postgresStore.QueryRow("SELECT version();").Scan(&postgresVersion)
	if err != nil {
		return nil, err
	}
	// Regular expression to find the version number.
	re := regexp.MustCompile(`\d+`)
	version := re.FindString(postgresVersion)

	listOfResults, scoreMap, err := postgres.PerformAllChecks(postgresStore, ctx, version, cnf.PostgresCheckSet)
	if err != nil {
		return nil, err
	}

	*resultPrintData += simpletextreport.PrintReportInFile(listOfResults, version, "Postgres Report")

	htmlreport.RegisterPostgresReportData(listOfResults, scoreMap, version)

	out := userlist.Run(postgresStore, ctx)
	*resultPrintData += "\nUsers Report"

	for _, data := range out {
		*resultPrintData += "> " + data.Title + "\n"
		*resultPrintData += data.Data.Text() + "\n"
	}

	return scoreMap, nil

}

func runRDS(ctx context.Context, _ *config.Config, resultMap *string) {
	fmt.Println("running RDS ")
	rds.Validate()
	*resultMap = simpletextreport.PrintReportInFile(rds.PerformAllChecks(ctx), "", "RDS Report")
	listOfResults := rds.PerformAllChecks(ctx)

	tableData := rds.ConvertToMainTable(listOfResults)
	output := strings.ReplaceAll(string(tableData), `\n`, "\n")

	fmt.Println("for detailed information check the generated output file rdssecreport.json")
	fmt.Println(output)

	tableData = rds.ConvertToTable(listOfResults)

	output = strings.ReplaceAll(string(tableData), `\n`, "\n")

	// write output data to file
	err := os.WriteFile("rdssecreport.json", []byte(output), 0600)
	if err != nil {
		fmt.Println("Error while saving result in file:", text.FgRed.Sprint(err))
		fmt.Println("**********listOfResults*************\n", string(tableData))
	}
	fmt.Println("rdssecreport.json file generated")
}
func runHBAScanner(ctx context.Context, cnf *config.Config, resultMap *string) ([]*model.HBAScannerResult, error) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return nil, err
	}
	listOfResults := hbascanner.HBAScanner(postgresStore, ctx)

	htmlreport.RegisterHBAReportData(listOfResults)

	for i := 0; i < len(listOfResults); i++ {
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\t", " ")
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\n", " ")
		if listOfResults[i].FailRows != nil {
			for j := 0; j < len(listOfResults[i].FailRows); j++ {
				listOfResults[i].FailRows[j] = strings.ReplaceAll(listOfResults[i].FailRows[j], "\t", " ")
			}
		}
	}

	*resultMap += "\nHBA Report\n" + simpletextreport.PrintHBAReportInFile(listOfResults) + "\n"

	return listOfResults, nil
}
func runHBAScannerByControl(ctx context.Context, cnf *config.Config) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return
	}
	result := hbascanner.HBAScannerByControl(postgresStore, ctx, cnf.App.Control)
	if result == nil {
		os.Exit(1)
	}

}

func runPostgresPasswordScanner(ctx context.Context, cnf *config.Config) {

	fmt.Print("\n****************************************************************")
	fmt.Print("\n** Don't use Password attack simulator feature in production. **")
	fmt.Print("\n** Please copy your users to test environment and try there.  **")
	fmt.Print("\n****************************************************************\n\n")

	// var host, port string
	// fmt.Printf("Enter Your Postgres Host (Default localhost): ")
	// fmt.Scanln(&host)
	// if host == "" {
	// 	host = "localhost"
	// }
	// fmt.Printf("Enter Your Postgres Port for Host %s (Default 5432): ", host)
	// fmt.Scanln(&port)
	// if port == "" {
	// 	port = "5432"
	// }

	// var bufferSize int
	// fmt.Printf("Enter number of passwords to be bufferred (Default 1000000): ")
	// fmt.Scanln(&bufferSize)
	// if bufferSize != 0 {
	// 	passwordmanager.ChannelBufferSize = bufferSize
	// }

	// var attemptSize int
	// fmt.Printf("Enter number of auths to be performed in parallel for a user (Disabled for 0 & 1): ")
	// fmt.Scanln(&attemptSize)
	// if attemptSize != 0 {
	// 	passwordmanager.GoroutinesPerUser = attemptSize
	// }

	var path string
	fmt.Printf("Enter path to the passwords files (Default /etc/klouddbshield/passwords): ")
	fmt.Scanln(&path) //nolint:errcheck
	if path == "" {
		path = "/etc/klouddbshield/passwords"
	}
	passwordmanager.ParentDir = path

	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return
	}
	listOfUsers, _ := passwordmanager.GetPostgresUsers(postgresStore)
	fmt.Println("listOfUsers:", listOfUsers)
	ctx, cancelFunc := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancelFunc()

	host := cnf.Postgres.Host
	port := cnf.Postgres.Port

	passwordmanager.PostgresPasswordScanner(ctx, host, port, listOfUsers)
}

func runPasswordGenerator(_ context.Context, cnf *config.Config) {
	var passwordLength, digitsCount, uppercaseCount, specialCount int

	fmt.Printf("Enter password length (Default %v): ", cnf.GeneratePassword.Length)
	fmt.Scanln(&passwordLength) //nolint:errcheck
	if passwordLength == 0 {
		passwordLength = cnf.GeneratePassword.Length
	}

	fmt.Printf("Enter number of digits (Default %v): ", cnf.GeneratePassword.NumberCount)
	fmt.Scanln(&digitsCount) //nolint:errcheck
	if digitsCount == 0 {
		digitsCount = cnf.GeneratePassword.NumberCount
	}

	fmt.Printf("Enter number of uppercase characters (Default %v): ", cnf.GeneratePassword.NumUppercase)
	fmt.Scanln(&uppercaseCount) //nolint:errcheck
	if uppercaseCount == 0 {
		uppercaseCount = cnf.GeneratePassword.NumUppercase
	}

	fmt.Printf("Enter number of special characters (Default %v): ", cnf.GeneratePassword.SpecialCharCount)
	fmt.Scanln(&specialCount) //nolint:errcheck
	if specialCount == 0 {
		specialCount = cnf.GeneratePassword.SpecialCharCount
	}

	passwd := passwordmanager.GeneratePassword(passwordLength, digitsCount, uppercaseCount, specialCount)

	fmt.Println(text.Bold.Sprint("Here's the password:"), passwd)

	encryptedPassword, err := passwordmanager.GenerateEncryptedPassword([]byte(passwd))
	if err != nil {
		return
	}

	fmt.Println(text.Bold.Sprint("Here's the encrypted password:"), encryptedPassword)
}

func runEncryptedPasswordGenerator(_ context.Context, _ *config.Config) {

	fmt.Print("Enter password: ")
	passwd, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return
	}
	fmt.Print("\r                    \n")

	encryptedPassword, err := passwordmanager.GenerateEncryptedPassword(passwd)
	if err != nil {
		return
	}

	fmt.Println(text.Bold.Sprint("Here's the encrypted password:"), encryptedPassword)
	fmt.Println()
}

func runPwnedUsers(ctx context.Context, cnf *config.Config, fileData *string) error {
	pgUsernameMap := map[string]struct{}{}
	for _, userName := range passwordmanager.PGUsernameList {
		pgUsernameMap[userName] = struct{}{}
	}

	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return fmt.Errorf("error opening postgres connection: %v", err)
	}

	listOfUsers, _ := passwordmanager.GetPostgresUsers(postgresStore)

	commonUserNames := []string{}
	for _, userName := range listOfUsers {
		if _, exists := pgUsernameMap[userName]; exists {
			commonUserNames = append(commonUserNames, userName)
		}
	}

	if cnf.App.PrintSummaryOnly {
		fmt.Println(text.Bold.Sprint("Password Manager Report:"))

		*fileData += fmt.Sprintln("Password Manager Report:")
		if len(commonUserNames) > 0 {
			*fileData += fmt.Sprintf("> Found these common usernames in the database: %s\n", strings.Join(commonUserNames, ", "))
		} else {
			*fileData += fmt.Sprintln("> No common usernames found in the database.")
		}
	}
	if len(commonUserNames) > 0 {
		fmt.Printf("> Found these common usernames in the database: %s\n", strings.Join(commonUserNames, ", "))
	} else {
		fmt.Println("> No common usernames found in the database.")
	}
	fmt.Println("")

	htmlreport.RenderPasswordManagerReport(ctx, commonUserNames)
	return nil
}

func runPwnedPassword(_ context.Context, cnf *config.Config) {
	dir := "./pwnedpasswords"
	if cnf.App.InputDirectory != "" {
		dir = cnf.App.InputDirectory
	}

	stat, err := os.Stat(dir)
	if err != nil || !stat.IsDir() {
		fmt.Println("You need to download the pawnedpasswords file and put it under pwnedpasswords subdirectory to use this feature. Please refer to our github repo readme for further instructions.")
		return
	}

	password := ""
	fmt.Print("Enter password to be checked: ")
	fmt.Scanln(&password) //nolint:errcheck
	if password == "" {
		fmt.Println("Password cannot be blank")
		return
	}

	times, err := passwordmanager.IsPasswordPwned(password, dir)
	if err != nil {
		if err == passwordmanager.ErrPasswordIsPwned {
			fmt.Println("The password is pwned for", times, "times")
		} else {
			fmt.Println("Error:", text.FgRed.Sprint(err))
		}
	} else {
		fmt.Println("Congratulations! The password is not pwned.")
	}

}
