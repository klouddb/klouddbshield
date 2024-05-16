package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/passwordmanager"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/hbarules"
	"github.com/klouddb/klouddbshield/pkg/logger"
	"github.com/klouddb/klouddbshield/pkg/mysqldb"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/runner"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/klouddb/klouddbshield/postgres/hbascanner"
	"github.com/klouddb/klouddbshield/rds"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

	htmlHelper := &htmlreport.HTMLHelper{}
	resultMap := map[string]interface{}{}
	defer func() {
		if len(resultMap) != 0 {
			saveResultInFile(resultMap)
		}
		generated, err := htmlHelper.Generate("report.html", 0600)
		if !generated {
			return
		}
		if err != nil {
			log.Error().Err(err).Msg("Unable to generate report.html file: " + err.Error())
		} else {
			fmt.Println("HTML report generated")
		}

	}()

	// Program context
	ctx := context.Background()
	if cnf.App.VerbosePostgres {
		runPostgresByControl(ctx, cnf)
		return
	}
	if cnf.App.RunMySql {
		runMySql(ctx, cnf, resultMap)
	}
	if cnf.App.RunPostgres {
		runPostgres(ctx, cnf, htmlHelper, resultMap)

	}
	if cnf.App.RunRds {
		runRDS(ctx, cnf, resultMap)
	}
	if cnf.App.HBASacanner {
		runHBAScanner(ctx, cnf, htmlHelper, resultMap)
	}
	if cnf.App.VerboseHBASacanner {
		runHBAScannerByControl(ctx, cnf)
	}

	if cnf.LogParser != nil {
		// run log parser
		// controlling number of cores used by log parser to 1
		runtime.GOMAXPROCS(1)

		var store *sql.DB
		if cnf.Postgres != nil {
			var err error
			store, _, err = postgresdb.Open(*cnf.Postgres)
			if err != nil {
				fmt.Println("Error while connecting to database: ", err)
			}
		}
		updatePgSettings(ctx, store, cnf.LogParser.PgSettings)

		switch cnf.LogParser.Command {
		case cons.LogParserCMD_UniqueIPs:
			runUniqueIPLogParser(ctx, cnf)
		case cons.LogParserCMD_InactiveUsr:
			runInactiveUSersLogParser(ctx, cnf, store)
		// case cons.LogParserCMD_MismatchIPs:
		// 	runMismatchIPsLogParser(ctx, cnf)
		case cons.LogParserCMD_HBAUnusedLines:
			runHBAUnusedLinesLogParser(ctx, cnf, store)
		default:
			fmt.Println("Invalid command for log parser")
			os.Exit(1)
		}
	}

	if cnf.App.RunPostgresConnTest {
		runPostgresPasswordScanner(ctx, cnf)
	}

	if cnf.App.RunGeneratePassword {
		runPasswordGenerator(ctx, cnf)
	}

	if cnf.App.RunPwnedUsers {
		runPwnedUsers(ctx, cnf)
	}

	if cnf.App.RunPwnedPasswords {
		runPwnedPassword(ctx, cnf)
	}
}

func updatePgSettings(ctx context.Context, store *sql.DB, pgSettings *model.PgSettings) {
	if store == nil {
		return
	}
	ps, err := utils.GetPGSettings(ctx, store)
	if err != nil {
		fmt.Println("Error while getting postgres settings: ", err)
		os.Exit(1)
	}

	pgSettings.LogConnections = ps.LogConnections
}

func runHBAUnusedLinesLogParser(ctx context.Context, cnf *config.Config, store *sql.DB) {

	// check if postgres setting contains required variable or connection logs
	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%h") && !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%r") {
		fmt.Println("Please set log_line_prefix to '%h' or '%r' or enable log_connections")
		return
	}

	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%u") || !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%d") {
		fmt.Printf("In logline prefix, please set '%s' and '%s'\n", "%u", "%d") // using printf to avoid the warning for %d in println
		return
	}

	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)

	var hbaRules []model.HBAFIleRules

	// if user is passing hba conf file manually then he or she are expecting that file to be scanned
	if cnf.LogParser.HbaConfFile != "" {
		var err error
		hbaRules, err = hbarules.ScanHBAFile(ctx, store, cnf.LogParser.HbaConfFile)
		if err != nil {
			fmt.Println("Got error while scanning hba file:", err)
			return
		}
	} else if store != nil {
		var err error
		hbaRules, err = utils.GetDatabaseAndHostForUSerFromHbaFileRules(ctx, store)
		if err != nil {
			fmt.Println("Got error while getting hba rules:", err)
			return
		}
	} else {
		fmt.Println("Please provide hba file or database connection")
		return
	}

	hbaValidator, err := hbarules.ParseHBAFileRules(hbaRules)
	if err != nil {
		fmt.Println("Got error while parsing hba rules:", err)
		return
	}

	hbaUnusedLineParser := parselog.NewHbaUnusedLines(cnf, baseParser, hbaValidator)
	runner.RunFastParser(ctx, cnf, hbaUnusedLineParser.Feed, parselog.GetBaseParserValidator(baseParser))

	if ctx.Err() != nil {
		fmt.Println("file parsing is taking longer then expected, please check the file or errors in" + logger.GetLogFileName())
		return
	}

	fmt.Println("")
	fmt.Println("Unused lines found from given log file:", hbaValidator.GetUnusedLines())
	fmt.Println("")
}

func runMismatchIPsLogParser(ctx context.Context, cnf *config.Config) {

	// check if postgres setting contains required variable or connection logs
	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%h") && !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%r") && !cnf.LogParser.PgSettings.LogConnections {
		fmt.Println("Please set log_line_prefix to '%h' or '%r' or enable log_connections")
		return
	}

	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)

	uniqueIPparser := parselog.NewUniqueIPParser(cnf, baseParser)

	runner.RunFastParser(ctx, cnf, uniqueIPparser.Feed, parselog.GetBaseParserValidator(baseParser))

	if ctx.Err() != nil {
		fmt.Println("file parsing is taking longer then expected, please check the file or errors in " + logger.GetLogFileName())
		return
	}

	if len(uniqueIPparser.GetUniqueIPs()) == 0 {
		fmt.Println("\nNo unique IPs found in the file please check the file or errors in " + logger.GetLogFileName())
		return
	}

	err := printMisMatchIPs(cnf.LogParser.OutputType, cnf.LogParser.IpFilePath, uniqueIPparser.GetUniqueIPs())
	if err != nil {
		fmt.Println("Got error while matching IPs from the file:", err)
	}

}

func printMisMatchIPs(outputType, filePath string, uniqueIPs map[string]bool) error {

	readFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error while opening file (%s): %v", filePath, err)
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	mismatchIps := []string{}

	for fileScanner.Scan() {
		_, ok := uniqueIPs[fileScanner.Text()]
		if !ok {
			mismatchIps = append(mismatchIps, fileScanner.Text())
		}
	}

	if len(mismatchIps) == 0 {
		fmt.Println("\nNo mismatch IPs found")
		return nil
	}

	fmt.Println("\nMismatch IPs:")
	if outputType == "json" {
		// print mismatch ips in json format
		out, _ := json.MarshalIndent(mismatchIps, "", "\t")
		fmt.Println(string(out))
		return nil
	}

	for _, ip := range mismatchIps {
		fmt.Println("\t" + ip)
	}

	return nil
}

func runInactiveUSersLogParser(ctx context.Context, cnf *config.Config, store *sql.DB) {
	// check if postgres setting contains required variable or connection logs
	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%u") && !cnf.LogParser.PgSettings.LogConnections {
		fmt.Println("Please set log_line_prefix to '%u' or enable log_connections")
		return
	}

	userdata, err := compareInvalidUserFromDatabaseAndLog(ctx, cnf, store)
	if err != nil {
		fmt.Println("Got error while comparing users from database and log file: ", err)
		return
	}

	if ctx.Err() != nil {
		fmt.Println("file parsing is taking longer then expected, please check the file or errors in" + logger.GetLogFileName())
		return
	}

	if len(userdata) == 0 || len(userdata[1]) == 0 {
		fmt.Println("No users found in log file. please check the log file or errors in " + logger.GetLogFileName())
		return
	}

	// userdata[0] contains users from database
	// userdata[1] contains users from log file
	// userdata[2] contains inactive users from database

	if cnf.LogParser.OutputType == "json" {
		out, _ := json.MarshalIndent(userdata, "", "\t")
		fmt.Println(string(out))
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	if len(userdata[0]) > 0 {
		table.Append([]string{"Users from DB", strings.Join(userdata[0], ", ")})
	}
	table.Append([]string{"Users from log", strings.Join(userdata[1], ", ")})
	if len(userdata[2]) > 0 {
		table.Append([]string{"Inactive users in db", strings.Join(userdata[2], ", ")})
	}

	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.Render()

}

// compareInvalidUserFromDatabaseAndLog will compare users from database and log file
func compareInvalidUserFromDatabaseAndLog(ctx context.Context, cnf *config.Config, postgresStore *sql.DB) ([][]string, error) {

	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)

	userParser := parselog.NewUserParser(cnf, baseParser)
	runner.RunFastParser(ctx, cnf, userParser.Feed, parselog.GetBaseParserValidator(baseParser))

	uniqueUsers := userParser.GetUniqueUser()

	usersFromLog := sort.StringSlice{}
	for user := range uniqueUsers {
		usersFromLog = append(usersFromLog, user)
	}
	usersFromLog.Sort()

	if postgresStore == nil {
		return [][]string{nil, usersFromLog, nil}, nil
	}

	usersFromDb, err := utils.GetPGUsers(ctx, postgresStore)
	if err != nil {
		fmt.Println("Error while fetching users from database: ", err)
	}

	inactiveUsers := sort.StringSlice{}
	for _, user := range usersFromDb {
		_, ok := uniqueUsers[user]
		if !ok {
			inactiveUsers = append(inactiveUsers, user)
		}
	}
	inactiveUsers.Sort()

	return [][]string{usersFromDb, usersFromLog, inactiveUsers}, nil
}

func runUniqueIPLogParser(ctx context.Context, cnf *config.Config) {

	// check if postgres setting contains required variable or connection logs
	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%h") && !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%r") && !cnf.LogParser.PgSettings.LogConnections {
		fmt.Println("Please set log_line_prefix to '%h' or '%r' or enable log_connections")
		return
	}

	baseParser := parselog.GetDynamicBaseParser(cnf.LogParser.PgSettings.LogLinePrefix)

	uniqueIPparser := parselog.NewUniqueIPParser(cnf, baseParser)
	runner.RunFastParser(ctx, cnf, uniqueIPparser.Feed, parselog.GetBaseParserValidator(baseParser))

	if ctx.Err() != nil {
		fmt.Println("file parsing is taking longer then expected, please check the file or errors in " + logger.GetLogFileName())
		return
	}

	if len(uniqueIPparser.GetUniqueIPs()) == 0 {
		fmt.Println("\nNo unique IPs found from given log file please check the file or errors in " + logger.GetLogFileName())
		return
	}

	fmt.Println("\nUnique IPs found from given log file:")

	ips := sort.StringSlice{}
	for ip := range uniqueIPparser.GetUniqueIPs() {
		ips = append(ips, ip)
	}

	ips.Sort()

	if cnf.LogParser.OutputType == "json" {
		out, _ := json.MarshalIndent(ips, "", "\t")
		fmt.Println(string(out))
		return
	}

	for _, ip := range ips {
		fmt.Println("\t" + ip)
	}

}

func saveResultInFile(result interface{}) {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling list of results:", err)
		return
	}

	err = os.WriteFile("report.json", []byte(jsonData), 0600)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate rdssecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
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
		switch ty := result.FailReason.(type) {

		case string:

			t.AppendRow(table.Row{"Fail Reason", result.FailReason})
		case []map[string]interface{}:
			failReason := ""
			for _, n := range ty {
				for key, value := range n {
					failReason += fmt.Sprintf("%s:%v, ", key, value)
				}
				failReason += "\n"

			}
			t.AppendRow(table.Row{"Fail Reason", failReason})
		default:
			var r = reflect.TypeOf(t)
			fmt.Printf("Other:%v\n", r)
		}

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
func runMySql(ctx context.Context, cnf *config.Config, resultMap map[string]interface{}) {
	mysqlDatabase := cnf.MySQL
	mysqlStore, _, err := mysqldb.Open(*mysqlDatabase)
	if err != nil {
		return
	}
	resultMap["mysql"] = mysql.PerformAllChecks(mysqlStore, ctx)
}
func runPostgres(ctx context.Context, cnf *config.Config, h *htmlreport.HTMLHelper, resultMap map[string]interface{}) []*model.Result {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return nil
	}
	listOfResults := postgres.PerformAllChecks(postgresStore, ctx)
	resultMap["Postgres"] = listOfResults

	data := htmlreport.GenerateHTMLReport(listOfResults, "Postgres")
	h.AddTab("Postgres", data)

	return listOfResults

}

func runRDS(ctx context.Context, cnf *config.Config, resultMap map[string]interface{}) {
	fmt.Println("running RDS ")
	rds.Validate()
	resultMap["RDS"] = rds.PerformAllChecks(ctx)
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
		log.Error().Err(err).Msg("Unable to generate rdssecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(tableData))
	}
	fmt.Println("rdssecreport.json file generated")
}
func runHBAScanner(ctx context.Context, cnf *config.Config, h *htmlreport.HTMLHelper, resultMap map[string]interface{}) []*model.HBAScannerResult {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return nil
	}
	listOfResults := hbascanner.HBAScanner(postgresStore, ctx)

	data := htmlreport.GenerateHTMLReportForHBA(listOfResults)
	h.AddTab("HBA Scanner Report", data)

	for i := 0; i < len(listOfResults); i++ {
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\t", " ")
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\n", " ")
		if listOfResults[i].FailRows != nil {
			for j := 0; j < len(listOfResults[i].FailRows); j++ {
				listOfResults[i].FailRows[j] = strings.ReplaceAll(listOfResults[i].FailRows[j], "\t", " ")
			}
		}
	}

	resultMap["HBA Scanner"] = listOfResults

	return listOfResults
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
	fmt.Scanln(&path)
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

func runPasswordGenerator(ctx context.Context, cnf *config.Config) {
	var passwordLength, digitsCount, uppercaseCount, specialCount int

	fmt.Printf("Enter password length (Default %v): ", cnf.GeneratePassword.Length)
	fmt.Scanln(&passwordLength)
	if passwordLength == 0 {
		passwordLength = cnf.GeneratePassword.Length
	}

	fmt.Printf("Enter number of digits (Default %v): ", cnf.GeneratePassword.NumberCount)
	fmt.Scanln(&digitsCount)
	if digitsCount == 0 {
		digitsCount = cnf.GeneratePassword.NumberCount
	}

	fmt.Printf("Enter number of uppercase characters (Default %v): ", cnf.GeneratePassword.NumUppercase)
	fmt.Scanln(&uppercaseCount)
	if uppercaseCount == 0 {
		uppercaseCount = cnf.GeneratePassword.NumUppercase
	}

	fmt.Printf("Enter number of special characters (Default %v): ", cnf.GeneratePassword.SpecialCharCount)
	fmt.Scanln(&specialCount)
	if specialCount == 0 {
		specialCount = cnf.GeneratePassword.SpecialCharCount
	}

	passwd := passwordmanager.GeneratePassword(passwordLength, digitsCount, uppercaseCount, specialCount)

	fmt.Println("Here's the password:", passwd)
}

func runPwnedUsers(ctx context.Context, cnf *config.Config) {
	pgUsernameMap := map[string]struct{}{}
	for _, userName := range passwordmanager.PGUsernameList {
		pgUsernameMap[userName] = struct{}{}
	}

	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		fmt.Println(err)
		return
	}

	listOfUsers, _ := passwordmanager.GetPostgresUsers(postgresStore)

	commonUserNames := []string{}
	for _, userName := range listOfUsers {
		if _, exists := pgUsernameMap[userName]; exists {
			commonUserNames = append(commonUserNames, userName)
		}
	}

	if len(commonUserNames) > 0 {
		fmt.Printf("Found these common usernames in the database: %s\n", strings.Join(commonUserNames, ", "))
	}
}

func runPwnedPassword(ctx context.Context, cnf *config.Config) {
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
	fmt.Scanln(&password)
	if password == "" {
		fmt.Println("Password cannot be blank")
		return
	}

	times, err := passwordmanager.IsPasswordPwned(password, dir)
	if err != nil {
		if err == passwordmanager.ErrPasswordIsPwned {
			fmt.Println("The password is pwned for", times, "times")
		} else {
			fmt.Println("Error:", err)
		}
	} else {
		fmt.Println("Congratulations! The password is not pwned.")
	}

}
