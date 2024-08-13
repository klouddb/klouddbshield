package config

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type Config struct {
	MySQL    *MySQL               `toml:"mysql"`
	Postgres *postgresdb.Postgres `toml:"postgres"`
	App      App                  `toml:"app"`

	CustomTemplate string `toml:"customTemplate"`

	PostgresCheckSet utils.Set[string]

	LogParser          *LogParser
	LogParserConfigErr error

	GeneratePassword *GeneratePassword `toml:"generatePassword"`

	Crons []Cron `toml:"crons"`
	// RunCrons bool   `toml:"-"`

	Email *AuthConfig `toml:"email"`

	PiiScannerConfig *piiscanner.Config `toml:"-"`
}

func NewPiiInteractiveMode(pgConfig *postgresdb.Postgres, printAll, spacyOnly, summary bool) (*piiscanner.Config, error) {
	if pgConfig == nil {
		return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}

	reader := newInputReader()

	var readOption string
	if !spacyOnly {
		readOption = strings.TrimSpace(reader.Read("Please enter run option", piiscanner.RunOption_DataScan_String))
		_, ok := piiscanner.RunOptionMap[readOption]
		if !ok {
			return nil, fmt.Errorf("invalid run option %s, valid options are %s", readOption, strings.Join(piiscanner.RunOptionSlice(), ", "))
		}
	}
	readExcludeTable := strings.TrimSpace(reader.Read("Please enter exclude tables ( e.g table1,table2,table3 )", ""))
	readIncludeTable := strings.TrimSpace(reader.Read("Please enter include tables ( e.g table1,table2,table3 )", ""))

	readDatabase := strings.TrimSpace(reader.Read("Please enter database name", pgConfig.DBName))
	readSchema := strings.TrimSpace(reader.Read("Please enter schema name", "public"))

	fmt.Println()

	return piiscanner.NewConfig(pgConfig, readOption, readExcludeTable,
		readIncludeTable, readDatabase, readSchema, printAll, spacyOnly, summary)
}

type AuthConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

type LogParser struct {
	Commands []string

	PgSettings *model.PgSettings

	Begin time.Time
	End   time.Time

	LogFiles []string

	// IpFilePath string

	HbaConfFile string

	OutputType string
}

func NewLogParser(logParser string, beginTime, endTime, prefix, logfile, hbaConfigFile string) (*LogParser, error) {
	commands := []string{logParser}
	if logParser == "all" {
		commands = []string{}
		for _, cmd := range cons.LogParserChoiseMapping {
			if cmd == cons.LogParserCMD_All {
				continue
			}
			commands = append(commands, cmd)
		}

		// added sorting to make sure the order is same in output
		sort.StringSlice(commands).Sort()
	}

	prefix = strings.TrimSpace(prefix)
	logfile = strings.TrimSpace(logfile)
	// ipfile = strings.TrimSpace(ipfile)
	beginTime = strings.TrimSpace(beginTime)
	endTime = strings.TrimSpace(endTime)
	hbaConfigFile = strings.TrimSpace(hbaConfigFile)

	// Valid Command map
	validCommands := utils.NewSet[string]()
	for _, command := range cons.LogParserChoiseMapping {
		validCommands.Add(command)
	}

	for _, command := range commands {
		if !validCommands.Contains(command) {
			return nil, fmt.Errorf("invalid command %s, Valid Commands are %s.", command, strings.Join(validCommands.Slice(), " , "))
		}
	}

	if prefix == "" {
		return nil, fmt.Errorf("log line prefix is required")
	}

	var begin, end time.Time
	var err error
	if beginTime != "" {
		begin, err = time.Parse("2006-01-02 15:04:05", beginTime)
		if err != nil {
			return nil, fmt.Errorf("error while parsing begin time: %v", err)
		}
	}

	if endTime != "" {
		end, err = time.Parse("2006-01-02 15:04:05", endTime)
		if err != nil {
			return nil, fmt.Errorf("error while parsing end time: %v", err)
		}
	}

	// Get the list of files that match the pattern.
	files, err := filepath.Glob(logfile)
	if err != nil {
		return nil, fmt.Errorf("error while validating log file name %s (%v)", logfile, err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no file found for given pattern %s", logfile)
	}

	// if utils.NewSetFromSlice(commands).IsAvailable(cons.LogParserCMD_MismatchIPs) {
	// 	if ipfile == "" {
	// 		return nil, fmt.Errorf("ip file path is required for mismatch_ips command")
	// 	}
	// 	if _, err := os.Stat(ipfile); err != nil {
	// 		return nil, fmt.Errorf("error while validating ip file name %s (%v)", ipfile, err)
	// 	}
	// }

	return &LogParser{
		Commands: commands,

		PgSettings: &model.PgSettings{
			LogLinePrefix: prefix,
		},

		Begin: begin,
		End:   end,

		LogFiles: files,
		// IpFilePath:  ipfile,
		HbaConfFile: hbaConfigFile,
	}, nil
}

// IsValidTime checks if given time is between begin and end time
func (a *LogParser) IsValidTime(t time.Time) bool {
	// if begin and end time is not zero then check if t is between begin and end time
	if !a.Begin.IsZero() && a.Begin.After(t) {
		return false
	}

	if !a.End.IsZero() && a.End.Before(t) {
		return false
	}

	// if begin time or end time is not set then return true
	return true
}

type MySQL struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	// DBName      string `toml:"dbname"`
	// SSLmode     string `toml:"sslmode"`
	MaxIdleConn int `toml:"maxIdleConn"`
	MaxOpenConn int `toml:"maxOpenConn"`
}

func (p *MySQL) HtmlReportName() string {
	return fmt.Sprintf("mysql_%s:%s", p.Host, p.Port)
}

type GeneratePassword struct {
	Length           int `toml:"length"`
	NumberCount      int `toml:"numberCount"`
	NumUppercase     int `toml:"numUppercase"`
	SpecialCharCount int `toml:"specialCharCount"`
}

type App struct {
	Debug              bool   `toml:"debug"`
	Hostname           string `toml:"hostname"`
	Run                bool
	RunPostgres        bool
	RunMySql           bool
	RunRds             bool
	Verbose            bool
	Control            string
	VerboseRDS         bool
	VerboseMySQL       bool
	VerbosePostgres    bool
	HBASacanner        bool
	VerboseHBASacanner bool

	RunMysqlConnTest             bool
	RunPostgresConnTest          bool
	RunGeneratePassword          bool
	RunGenerateEncryptedPassword bool
	RunPwnedUsers                bool
	RunPwnedPasswords            bool
	InputDirectory               string
	UseDefaults                  bool
	ThrottlerLIMIT               int

	PrintSummaryOnly bool

	TransactionWraparound bool

	PrintProcessTime bool
}

var Version = "dev"

func NewConfig() (*Config, error) {
	var verbose bool
	var version bool
	var help bool
	var run bool
	var runPostgres bool
	var runMySql bool
	var runRds bool
	var control string
	var hbaScanner bool
	var runPostgresConnTest, runGeneratePassword, runGenerateEncryptedPassword, runPwnedUsers, runPwnedPassword bool
	var userDefaults bool
	var printSummaryReport bool
	var inputDirectory string
	var allchecks bool
	// var setupCron bool
	var printProcessTime bool
	flag.BoolVar(&verbose, "verbose", verbose, "As of today verbose only works for a specific control. Ex ciscollector -r --verbose --control 6.7")
	flag.StringVar(&control, "control", control, "Check verbose detail for individual control.\nMake sure to use this with --verbose option.\nEx: ciscollector -r --verbose --control 6.7")
	flag.BoolVar(&run, "r", run, "Run")
	flag.BoolVar(&allchecks, "allchecks", allchecks, "Run all checks")
	// flag.BoolVar(&setupCron, "setup-cron", setupCron, "Setup cron for ciscollector")
	flag.BoolVar(&printProcessTime, "process-time", printProcessTime, "Print process time")

	var customTemplatePath string
	flag.StringVar(&customTemplatePath, "custom-template", customTemplatePath, "Custom template path for postgres checks")

	// flags related to log parsing
	var logParser string
	var logfile string
	flag.StringVar(&logParser, "logparser", logParser, `To run logparse using with flags. for more details use ciscollector --help`)
	flag.StringVar(&logfile, "file-path", "", "File path e.g /location/to/log/file.log. required for all commands in log parser. for more details use ciscollector --help")

	var beginTime, endTime string
	// read begin time
	flag.StringVar(&beginTime, "begin-time", "", "Begin time for log filtering. format supported [2006-01-02 15:04:05]. optional flag for log parser. for more details use ciscollector --help")
	// read end time
	flag.StringVar(&endTime, "end-time", "", "End time for log filtering. format supported [2006-01-02 15:04:05]. optional flag for log parser. for more details use ciscollector --help")
	var prefix string
	flag.StringVar(&prefix, "prefix", "", "Log line prefix for offline parsing. required for all commands in log parser")
	// var ipFilePath string
	// flag.StringVar(&ipFilePath, "ip-file-path", "", "File path for ip list. requered for mismatch_ips command in log parser") // TODO removed because we are not using missing_ip command
	var hbaConfigFile string
	flag.StringVar(&hbaConfigFile, "hba-file", "", "file path for pg_hba.conf. for unused_lines command in log parser")
	var outputType string
	flag.StringVar(&outputType, "output-type", "", "Output type for log parser. supported types are json, csv, table")
	var cpuLimit int
	flag.IntVar(&cpuLimit, "cpu-limit", cpuLimit, "CPU limit for log parser. default is 0")

	flag.BoolVar(&userDefaults, "y", run, "Use default options")
	flag.StringVar(&inputDirectory, "dir", "", "Directory")
	// flag.BoolVar(&hbaSacanner, "r", run, "Run")
	// flag.BoolVar(&runMySql, "run-mysql", runMySql, "Run MySQL")
	// flag.BoolVar(&runPostgres, "run-postgres", runPostgres, "Run Postgres")
	// flag.BoolVar(&runRds, "run-rds", runRds, "Run AWS RDS")
	// flag.BoolVar(&verbose, "v", verbose, "Verbose")
	flag.BoolVar(&version, "version", version, "Print version")
	flag.BoolVar(&help, "help", help, "Print help")
	flag.BoolVar(&help, "h", help, "Print help")

	var piiscannerRunOption, excludeTable, includeTable, database, schema string
	var printAllResults, spacyOnly, printSummaryOnly bool
	flag.StringVar(&piiscannerRunOption, "piiscanner", "", "Run pii scanner")
	flag.StringVar(&excludeTable, "exclude-table", "", "Exclude table for pii scanner")
	flag.StringVar(&includeTable, "include-table", "", "Include table for pii scanner")
	flag.StringVar(&database, "database", "", "Database name for pii scanner")
	flag.StringVar(&schema, "schema", "public", "Schema name for pii scanner")
	flag.BoolVar(&printAllResults, "print-all", false, "Print all results for pii scanner")
	flag.BoolVar(&spacyOnly, "spacy-only", false, "Run spacy only for pii scanner")
	flag.BoolVar(&printSummaryOnly, "print-summary", false, "Print summary only for pii scanner")

	var transactionWraparound bool
	flag.BoolVar(&transactionWraparound, "transaction-wraparound", transactionWraparound, "Generate transaction wraparound report")

	flag.Parse()

	if cpuLimit != 0 {
		runtime.GOMAXPROCS(cpuLimit)
	}

	// if setupCron {
	// 	c, err := LoadConfig()
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	c.RunCrons = true
	// 	return c, nil
	// }

	if version {
		log.Debug().Str("version", Version).Send()
		os.Exit(0)
	}
	if help {
		PrintHelp()
		os.Exit(0)
	}

	if !run && !verbose && !allchecks && logParser == "" && piiscannerRunOption == "" && !spacyOnly {
		fmt.Println("> For Help: " + text.FgGreen.Sprint("ciscollector --help"))
		os.Exit(0)
	}

	c := &Config{}
	if !runRds {
		var err error
		c, err = LoadConfig()
		if err != nil && logParser == "" {
			return nil, fmt.Errorf("loading config: %v", err)
		}
	}

	c.App.PrintProcessTime = printProcessTime

	var piiConfig *piiscanner.Config
	if piiscannerRunOption != "" || (spacyOnly && !run) {
		var err error
		piiConfig, err = piiscanner.NewConfig(c.Postgres, piiscannerRunOption, excludeTable,
			includeTable, database, schema, printAllResults, spacyOnly, printSummaryOnly)
		if err != nil {
			fmt.Println("Error in creating pii scanner config: ", text.FgHiRed.Sprint(err))
			os.Exit(1)
		}
	}

	// if controlVerbose != "" {
	// 	fmt.Print(controlVerbose)
	// }
	if allchecks {
		runPostgres = true
		hbaScanner = true
		logParser = cons.LogParserCMD_All
		runPwnedUsers = true
		printSummaryReport = true
		transactionWraparound = true
	} else if run && !verbose {
		if customTemplatePath != "" {
			fmt.Print(cons.MSG_ChoiseCustomTemplate)
		} else {
			fmt.Print(cons.MSG_Choise)
		}
		choice := 0
		fmt.Scanln(&choice) //nolint:errcheck
		switch choice {
		case 1: // All Postgres checks(Recommended)
			runPostgres = true
			hbaScanner = true
			logParser = cons.LogParserCMD_All
			runPwnedUsers = true
			printSummaryReport = true
			transactionWraparound = true

		case 2: // Postgres CIS and User Security checks
			runPostgres = true
			response := "N"
			fmt.Print("Do you also want to run HBA Scanner?(y/N):")
			fmt.Scanln(&response) //nolint:errcheck
			if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
				hbaScanner = true
			}

		case 3: // HBA Scanner
			hbaScanner = true

		case 4: // PII Db Scanner
			var err error
			piiConfig, err = NewPiiInteractiveMode(c.Postgres, printAllResults, spacyOnly, printSummaryOnly)
			if err != nil {
				fmt.Println("Error in creating pii scanner config: ", text.FgHiRed.Sprint(err))
				os.Exit(1)
			}

		case 5: // Inactive user report
			logParser = cons.LogParserCMD_InactiveUsr

		case 6: // Client ip report
			logParser = cons.LogParserCMD_UniqueIPs
		case 7: // HBA unused lines report
			logParser = cons.LogParserCMD_HBAUnusedLines

		case 8: // Password Manager
			fmt.Println("1. Password attack simulator")
			fmt.Println("2. Password generator")
			fmt.Println("3. Encrypt a password(scram-sha-256)")
			fmt.Println("4. Match common usernames")
			fmt.Println("5. Pawned password detector")
			fmt.Printf("Enter your choice to execute(1/2/3/4/5):")
			choice := 0
			fmt.Scanln(&choice) //nolint:errcheck
			switch choice {
			case 1:
				runPostgresConnTest = true
			case 2:
				runGeneratePassword = true
			case 3:
				runGenerateEncryptedPassword = true
			case 4:
				runPwnedUsers = true
			case 5:
				runPwnedPassword = true
			default:
				fmt.Println("Invalid Choice, Please Try Again.")
				os.Exit(1)
			}

		case 9: // Password leak scanner
			logParser = cons.LogParserCMD_PasswordLeakScanner

		case 10: // AWS RDS Sec Report
			runRds = true

		case 11: // AWS Aurora Sec Report
			runRds = true

		case 12: // MySQL Report
			runMySql = true

		case 13: // Transaction Wraparound
			transactionWraparound = true

		case 14: // Exit
			os.Exit(0)

		default:
			fmt.Println("Invalid Choice, Please Try Again.")
			os.Exit(1)
		}
	}

	c.PiiScannerConfig = piiConfig
	c.PostgresCheckSet = utils.NewDummyContainsAllSet[string]()

	if customTemplatePath != "" {
		c.CustomTemplate = customTemplatePath
	}

	if c.CustomTemplate != "" {
		var checkNumbers []string
		var err error
		if strings.HasSuffix(c.CustomTemplate, ".json") {
			checkNumbers, err = utils.LoadJsonTemplate(c.CustomTemplate)
		} else if strings.HasSuffix(c.CustomTemplate, ".csv") {
			checkNumbers, err = utils.LoadCSVTemplate(c.CustomTemplate)
		} else {
			return nil, fmt.Errorf("Invalid file format. Supported formats are json and csv")
		}

		if err != nil {
			return nil, fmt.Errorf("loading custom template: %v", err)
		}

		c.PostgresCheckSet = utils.NewSetFromSlice(checkNumbers)
	}

	c.App.Run = run
	c.App.RunMySql = runMySql
	c.App.RunPostgres = runPostgres
	c.App.RunRds = runRds
	c.App.Verbose = verbose
	c.App.Control = control
	c.App.HBASacanner = hbaScanner
	c.App.RunPostgresConnTest = runPostgresConnTest
	c.App.RunPwnedUsers = runPwnedUsers
	c.App.RunPwnedPasswords = runPwnedPassword
	c.App.RunGeneratePassword = runGeneratePassword
	c.App.RunGenerateEncryptedPassword = runGenerateEncryptedPassword
	c.App.UseDefaults = userDefaults
	c.App.InputDirectory = inputDirectory
	c.App.PrintSummaryOnly = printSummaryReport
	c.App.TransactionWraparound = transactionWraparound
	c.PiiScannerConfig = piiConfig

	if run && verbose {
		if customTemplatePath != "" {
			fmt.Print(cons.MSG_ChoiseCustomTemplate)
		} else {
			fmt.Print(cons.MSG_Choise)
		}
		choice := 0
		fmt.Scanln(&choice) //nolint:errcheck

		switch choice {
		case 1: // All Postgres checks(Recommended)
			if c.App.Verbose && c.Postgres != nil {
				c.App.VerbosePostgres = true
			} else {
				fmt.Println(cons.Err_PostgresConfig_Missing)
				os.Exit(1)
			}

			if c.App.Verbose && c.Postgres != nil {
				c.App.VerboseHBASacanner = true
			} else {
				fmt.Println(cons.Err_PostgresConfig_Missing)
				os.Exit(1)
			}

			c.App.PrintSummaryOnly = true
			logParser = cons.LogParserCMD_All
			c.App.RunPwnedUsers = true
			c.App.TransactionWraparound = true

		case 2: // Postgres checks
			if c.App.Verbose && c.Postgres != nil {
				c.App.VerbosePostgres = true
			} else {
				fmt.Println(cons.Err_PostgresConfig_Missing)
				os.Exit(1)
			}

		case 3: // HBA Scanner
			if c.App.Verbose && c.Postgres != nil {
				c.App.VerboseHBASacanner = true
			} else {
				fmt.Println(cons.Err_PostgresConfig_Missing)
				os.Exit(1)
			}
		case 4: // PII DB Scanner
			fmt.Println("Verbose feature is not available for PII DB Scanner yet .. Will be added in future releases")
		case 5: // Inactive user report
			fmt.Println("Verbose feature is not available for Inactive user yet .. Will be added in future releases")
			os.Exit(1)
		case 6: // Client ip report
			fmt.Println("Verbose feature is not available for Client IP user yet .. Will be added in future releases")
			os.Exit(1)
		case 7: // HBA unused lines report
			fmt.Println("Verbose feature is not available for HBA Unused lines yet .. Will be added in future releases")
			os.Exit(1)
		case 8: // Password Manager
			fmt.Println("1. Password attack simulator")
			fmt.Println("2. Password generator")
			fmt.Println("3. Encrypt a password(scram-sha-256)")
			fmt.Println("4. Match common usernames")
			fmt.Println("5. Pawned password detector")
			fmt.Printf("Enter your choice to execute(1/2/3/4/5):")
			choice := 0
			fmt.Scanln(&choice) //nolint:errcheck
			switch choice {
			case 1:
				c.App.RunPostgresConnTest = true
			case 2:
				c.App.RunGeneratePassword = true
			case 3:
				c.App.RunGenerateEncryptedPassword = true
			case 4:
				c.App.RunPwnedUsers = true
			case 5:
				c.App.RunPwnedPasswords = true
			default:
				fmt.Println("Invalid Choice, Please Try Again.")
				os.Exit(1)
			}
		case 9: // Password leak scanner
			fmt.Println("Verbose feature is not available for Password Leak lines yet .. Will be added in future releases")
			os.Exit(1)

		case 10: // AWS RDS Sec Report
			fmt.Println("Verbose feature is not available for MySQL and RDS yet .. Will be added in future releases")
			os.Exit(1)

		case 11: // AWS Aurora Sec Report
			fmt.Println("Verbose feature is not available for MySQL and RDS yet .. Will be added in future releases")
			os.Exit(1)
		case 12: // MySQL Report
			fmt.Println("Verbose feature is not available for MySQL and RDS yet .. Will be added in future releases")
			os.Exit(1)

		case 13: // Transaction Wraparound
			fmt.Println("Verbose feature is not available for Transactions yet .. Will be added in future releases")
			os.Exit(1)

		case 14:
			os.Exit(0)

		default:
			fmt.Println("Invalid Choice, Please Try Again.")
			os.Exit(1)
		}
	}

	var err error
	if c.App.Hostname == "" {
		c.App.Hostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("getting hostname: %v", err)
		}
	}
	if c.MySQL == nil && c.Postgres == nil && !runRds && c.LogParser == nil {
		return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}
	if c.MySQL != nil && c.Postgres != nil && !runRds {
		return nil, fmt.Errorf(cons.Err_MysqlConfig_Missing)
	}
	if c.MySQL == nil && runMySql {
		return nil, fmt.Errorf(cons.Err_OldversionSuggestion_Postgres)
	}

	postgresConfigNeeded := runPostgres || c.App.HBASacanner || c.PiiScannerConfig != nil || c.App.TransactionWraparound
	if c.Postgres == nil && postgresConfigNeeded {
		return nil, fmt.Errorf(cons.Err_OldversionSuggestion_Mysql)
	}
	if c.MySQL != nil && c.MySQL.User == "" && runMySql {
		fmt.Printf("Enter Your MySQL DB User: ")
		fmt.Scanln(&c.MySQL.User) //nolint:errcheck
	}
	if c.MySQL != nil && c.MySQL.Password == "" && runMySql {
		fmt.Printf("Enter Your DB MySQL Password for %s: ", c.MySQL.User)
		fmt.Scanln(&c.MySQL.Password) //nolint:errcheck
	}

	if c.Postgres != nil && c.Postgres.User == "" && postgresConfigNeeded {
		fmt.Printf("Enter Your Postgres DB User: ")
		fmt.Scanln(&c.Postgres.User) //nolint:errcheck
	}
	if c.Postgres != nil && c.Postgres.Password == "" && postgresConfigNeeded {
		fmt.Printf("Enter Your DB Postgres Password for %s: ", c.Postgres.User)
		fmt.Scanln(&c.Postgres.Password) //nolint:errcheck
	}

	if c.GeneratePassword == nil {
		c.GeneratePassword = &GeneratePassword{
			Length:           20,
			NumberCount:      2,
			NumUppercase:     2,
			SpecialCharCount: 2,
		}
	}

	if logParser != "" {
		if run || allchecks {
			c.LogParser, c.LogParserConfigErr = getLogParserInputs(c.Postgres, logParser)
		} else {
			var err error
			c.LogParser, err = NewLogParser(logParser, beginTime, endTime, prefix, logfile, hbaConfigFile)
			if err != nil {
				c.LogParserConfigErr = fmt.Errorf("Invalid input for logparser: %v", err)
			}
		}

		if c.LogParser != nil {
			c.LogParser.OutputType = outputType
		}
	}

	return c, nil
}

func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigName("kshieldconfig")
	v.AddConfigPath("./")
	v.AddConfigPath("/etc/klouddbshield")

	c := &Config{}

	err := v.ReadInConfig()
	if err != nil {
		return c, fmt.Errorf("fatal error config file: %v", err)
	}
	err = v.Unmarshal(c)
	if err != nil {
		return c, fmt.Errorf("unmarshal: %v", err)
	}

	return c, nil
}

type inputReader struct {
	reader *bufio.Reader
}

func newInputReader() *inputReader {
	return &inputReader{
		reader: bufio.NewReader(os.Stdin),
	}
}

func (i *inputReader) Read(msg, detault string) string {
	fmt.Print("> " + msg)
	if detault != "" {
		fmt.Print(" [" + detault + "]")
	}
	fmt.Print(": ")
	input, err := i.reader.ReadString('\n')
	if err != nil {
		fmt.Println("Invalid input for logparser:", err)
		os.Exit(1)
	}
	input = strings.TrimSuffix(input, "\n")
	input = strings.Trim(input, `"`)
	input = strings.Trim(input, "'")

	if input == "" {
		return detault
	}

	return input
}

func getLogParserInputs(postgresConf *postgresdb.Postgres, command string) (*LogParser, error) {

	if command == "" {
		return nil, fmt.Errorf("Invalid Choice, Please Try Again.")

	}

	hbaConfigSuggestion := ""
	prefixSuggestion := ""
	logfileSuggestion := ""
	store, _, err := postgresdb.Open(*postgresConf)
	if err == nil {
		defer store.Close()
		prefixSuggestion, _ = utils.GetLoglinePrefix(context.Background(), store)
		dataDir, _ := utils.GetDataDirectory(context.Background(), store)
		if dataDir != "" {
			logfileSuggestion = dataDir + "/log/*.log"
		}

		if command == cons.LogParserCMD_HBAUnusedLines || command == cons.LogParserCMD_All {
			hbaConfigSuggestion, _ = utils.GetHBAFilePath(context.Background(), store)
			if _, err := os.Stat(hbaConfigSuggestion); err != nil {
				hbaConfigSuggestion = ""
			}
		}
	}

	reader := newInputReader()

	prefix := reader.Read("Enter Log Line Prefix", prefixSuggestion)
	logfile := reader.Read("Enter Log File Path", logfileSuggestion)
	beginTime := reader.Read("Enter Begin Time (format: 2006-01-02 15:04:05) [optional]", "")
	endTime := reader.Read("Enter End Time (format: 2006-01-02 15:04:05) [optional]", "")

	// var ipfile string
	// if command == cons.LogParserCMD_MismatchIPs {
	// 	ipfile = reader.Read("Enter IP File Path: ")
	// }

	var hbaConfigFile string
	if command == cons.LogParserCMD_HBAUnusedLines || command == cons.LogParserCMD_All {
		hbaConfigFile = reader.Read("Enter pg_hba.conf File Path", hbaConfigSuggestion)
	}

	l, err := NewLogParser(command, beginTime, endTime, prefix, logfile, hbaConfigFile)
	if err != nil {
		return nil, fmt.Errorf("Invalid input for logparser: %v", err)
	}

	return l, nil
}

func MustNewConfig() *Config {
	config, err := NewConfig()
	if err != nil {
		fmt.Println("Can't create config")
		fmt.Println(err)
		fmt.Println(cons.Err_PostgresConfig_Missing)
		os.Exit(1)
	}

	return config
}
