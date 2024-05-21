package config

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
)

type Config struct {
	MySQL    *MySQL    `toml:"mysql"`
	Postgres *Postgres `toml:"postgres"`
	App      App       `toml:"app"`

	LogParser *LogParser

	GeneratePassword *GeneratePassword `toml:"generatePassword"`
}

type LogParser struct {
	Command string

	PgSettings *model.PgSettings

	Begin time.Time
	End   time.Time

	LogFiles []string

	IpFilePath string

	HbaConfFile string

	OutputType string
}

func NewLogParser(command, beginTime, endTime, prefix, logfile, ipfile, hbaConfigFile string) (*LogParser, error) {
	prefix = strings.TrimSpace(prefix)
	logfile = strings.TrimSpace(logfile)
	ipfile = strings.TrimSpace(ipfile)
	beginTime = strings.TrimSpace(beginTime)
	endTime = strings.TrimSpace(endTime)
	hbaConfigFile = strings.TrimSpace(hbaConfigFile)

	if command != cons.LogParserCMD_UniqueIPs && command != cons.LogParserCMD_InactiveUsr && command != cons.LogParserCMD_MismatchIPs && command != cons.LogParserCMD_HBAUnusedLines {
		return nil, fmt.Errorf("invalid command %s, please use unique_ip, mismatch_ips or inactive_users", command)
	}

	if prefix == "" {
		return nil, fmt.Errorf("log line prefix is required")
	}

	var begin, end time.Time
	var err error
	if beginTime != "" {
		begin, err = time.Parse("2006-01-02 15:04:05", beginTime)
		if err != nil {
			return nil, fmt.Errorf("error while parsing begin time: %w", err)
		}
	}

	if endTime != "" {
		end, err = time.Parse("2006-01-02 15:04:05", endTime)
		if err != nil {
			return nil, fmt.Errorf("error while parsing end time: %w", err)
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

	if command == cons.LogParserCMD_MismatchIPs {
		if ipfile == "" {
			return nil, fmt.Errorf("ip file path is required for mismatch_ips command")
		}
		if _, err := os.Stat(ipfile); err != nil {
			return nil, fmt.Errorf("error while validating ip file name %s (%v)", ipfile, err)
		}
	}

	return &LogParser{
		Command: command,

		PgSettings: &model.PgSettings{
			LogLinePrefix: prefix,
		},

		Begin: begin,
		End:   end,

		LogFiles:    files,
		IpFilePath:  ipfile,
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

type Postgres struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	// SSLmode     string `toml:"sslmode"`
	MaxIdleConn int `toml:"maxIdleConn"`
	MaxOpenConn int `toml:"maxOpenConn"`
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

type GeneratePassword struct {
	Length           int `toml:"length"`
	NumberCount      int `toml:"numberCount"`
	NumUppercase     int `toml:"numUppercase"`
	SpecialCharCount int `toml:"specialCharCount"`
}

type App struct {
	Debug              bool   `toml:"debug"`
	DryRun             bool   `toml:"dryRun"`
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

	RunMysqlConnTest    bool
	RunPostgresConnTest bool
	RunGeneratePassword bool
	RunPwnedUsers       bool
	RunPwnedPasswords   bool
	InputDirectory      string
	UseDefaults         bool
	ThrottlerLIMIT      int
}

var CONF *Config

var Version = "dev"

func NewConfig() (*Config, error) {
	var verbose bool
	var version bool
	var run bool
	var runPostgres bool
	var runMySql bool
	var runRds bool
	var control string
	var hbaScanner bool
	var runPostgresConnTest, runGeneratePassword, runPwnedUsers, runPwnedPassword bool
	var userDefaults bool
	var inputDirectory string
	flag.BoolVar(&verbose, "verbose", verbose, "As of today verbose only works for a specific control. Ex ciscollector -r --verbose --control 6.7")
	flag.StringVar(&control, "control", control, "Check verbose detail for individual control.\nMake sure to use this with --verbose option.\nEx: ciscollector -r --verbose --control 6.7")
	flag.BoolVar(&run, "r", run, "Run")

	// flags related to log parsing
	var logParser string
	var logfile string
	flag.StringVar(&logParser, "logparser", logParser, `To run Log Parser. Supported commands are:
1. unique_ip: To get unique IPs from log file NOTE: --begin-time and --end-time are optional flags and --prefix and --file-path are required flags if you are using --logparser=unique_ip
e.g
* ciscollector --logparser unique_ip --file-path /location/to/log/file.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix>
* ciscollector --logparser unique_ip --file-path /location/to/log/file.log --prefix <logline prefix>
* ciscollector --logparser unique_ip --file-path /location/to/log/*.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix>
* ciscollector --logparser unique_ip --file-path /location/to/log/*.log --prefix <logline prefix>

2. inactive_users: To get inactive users from log file	NOTE: --begin-time and --end-time are optional flags and --prefix and --file-path are required flags if you are using --logparser=inactive_users
e.g
* ciscollector --logparser inactive_users --file-path /location/to/log/file.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix>
* ciscollector --logparser inactive_users --file-path /location/to/log/file.log --prefix <logline prefix>
* ciscollector --logparser inactive_users --file-path /location/to/log/*.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix>
* ciscollector --logparser inactive_users --file-path /location/to/log/*.log --prefix <logline prefix>

3. unused_lines: To get unused lines from pg_hba.conf file by comparing that with log file
NOTE: --begin-time and --end-time are optional flags and --prefix, --file-path and --hba-file are required flags if you are using --logparser=unused_lines
e.g
* ciscollector --logparser unused_lines --file-path /location/to/log/file.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser unused_lines --file-path /location/to/log/file.log --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser unused_lines --file-path /location/to/log/*.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser unused_lines --file-path /location/to/log/*.log --prefix <logline prefix> --hba-file /location/to/pg_hba.conf

`)
	flag.StringVar(&logfile, "file-path", "", "File path e.g /location/to/log/file.log. required for all commands in log parser")

	var beginTime, endTime string
	// read begin time
	flag.StringVar(&beginTime, "begin-time", "", "Begin time for log filtering. format supported [2006-01-02 15:04:05]. optional flag for log parser")
	// read end time
	flag.StringVar(&endTime, "end-time", "", "End time for log filtering. format supported [2006-01-02 15:04:05]. optional flag for log parser")
	var prefix string
	flag.StringVar(&prefix, "prefix", "", "Log line prefix for offline parsing. required for all commands in log parser")
	var ipFilePath string
	// flag.StringVar(&ipFilePath, "ip-file-path", "", "File path for ip list. requered for mismatch_ips command in log parser") // TODO removed because we are not using missing_ip command
	var hbaConfigFile string
	flag.StringVar(&hbaConfigFile, "hba-file", "", "file path for pg_hba.conf. for unused_lines command in log parser")
	var outputType string
	flag.StringVar(&outputType, "output-type", "", "Output type for log parser. supported types are json, csv, table")

	flag.BoolVar(&userDefaults, "y", run, "Use default options")
	flag.StringVar(&inputDirectory, "dir", "", "Directory")
	// flag.BoolVar(&hbaSacanner, "r", run, "Run")
	// flag.BoolVar(&runMySql, "run-mysql", runMySql, "Run MySQL")
	// flag.BoolVar(&runPostgres, "run-postgres", runPostgres, "Run Postgres")
	// flag.BoolVar(&runRds, "run-rds", runRds, "Run AWS RDS")
	// flag.BoolVar(&verbose, "v", verbose, "Verbose")
	flag.BoolVar(&version, "version", version, "Print version")

	flag.Parse()

	var logParserConf *LogParser
	if logParser != "" {
		var err error
		logParserConf, err = NewLogParser(logParser, beginTime, endTime, prefix, logfile, ipFilePath, hbaConfigFile)
		if err != nil {
			fmt.Println("Invalid input for logparser:", err)
			flag.Usage()
			os.Exit(1)
		}

		logParserConf.OutputType = outputType
	}

	if version {
		log.Debug().Str("version", Version).Send()
		os.Exit(0)
	}
	if !run && !verbose && logParser == "" {
		flag.Usage()
		os.Exit(0)
	}
	// if controlVerbose != "" {
	// 	fmt.Print(controlVerbose)
	// }
	if run && !verbose {
		fmt.Print(cons.MSG_Choise)
		choice := 0
		fmt.Scanln(&choice)
		switch choice {
		case 1:
			runPostgres = true
			response := ""
			fmt.Println("Do you also want to run HBA Scanner?(y/n):")
			fmt.Scanln(&response)
			if response == "y" || response == "Y" {
				hbaScanner = true
			}
		case 2:
			runMySql = true
		case 3:
			runRds = true
		case 4:
			hbaScanner = true
		case 5:
			logParserConf = getLogParserInputs()
		case 6:
			fmt.Println("\n1.Password attack simulator\n2.Password generator\n3.Match common usernames\n4.Pawned password detector")
			fmt.Printf("Enter your choice to execute(1/2/3/4):")
			choice := 0
			fmt.Scanln(&choice)
			switch choice {
			case 1:
				runPostgresConnTest = true
			case 2:
				runGeneratePassword = true
			case 3:
				runPwnedUsers = true
			case 4:
				runPwnedPassword = true
			default:
				fmt.Println("Invalid Choice, Please Try Again.")
				os.Exit(1)
			}

		default:
			fmt.Println("Invalid Choice, Please Try Again.")
			os.Exit(1)
		}
	}

	c := &Config{}
	if !runRds {
		var err error
		c, err = loadConfig()
		if err != nil && logParserConf == nil {
			return nil, fmt.Errorf("loading config: %w", err)
		}
	}

	c.App.Run = run
	c.App.RunMySql = runMySql
	c.App.RunPostgres = runPostgres
	c.App.RunRds = runRds
	c.App.Verbose = verbose
	c.App.Control = control
	c.App.HBASacanner = hbaScanner
	c.LogParser = logParserConf
	c.App.RunPostgresConnTest = runPostgresConnTest
	c.App.RunPwnedUsers = runPwnedUsers
	c.App.RunPwnedPasswords = runPwnedPassword
	c.App.RunGeneratePassword = runGeneratePassword
	c.App.UseDefaults = userDefaults
	c.App.InputDirectory = inputDirectory
	if run && verbose {
		fmt.Print(cons.MSG_Choise)
		choice := 0
		fmt.Scanln(&choice)
		switch choice {
		case 1:
			if c.App.Verbose && c.Postgres != nil {
				c.App.VerbosePostgres = true
			} else {
				fmt.Println("Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate it with your dbname,username etc.. before using this utility. For additional details please check github readme.")
				os.Exit(1)
			}

		case 2:
			fmt.Println("Verbose feature is not available for MySQL and RDS yet .. Will be added in future releases")
			os.Exit(1)
		case 3:
			fmt.Println("Verbose feature is not available for MySQL and RDS yet .. Will be added in future releases")
			os.Exit(1)
		case 4:
			if c.App.Verbose && c.Postgres != nil {
				c.App.VerboseHBASacanner = true
			} else {
				fmt.Println("Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate it with your dbname,username etc.. before using this utility. For additional details please check github readme.")
				os.Exit(1)
			}
		case 5:
			c.LogParser = getLogParserInputs()
		case 6:
			fmt.Println("\n1.Password attack simulator\n2.Password generator\n3.Match common usernames\n4.Pawned password detector")
			fmt.Printf("Enter your choice to execute(1/2/3/4):")
			choice := 0
			fmt.Scanln(&choice)
			switch choice {
			case 1:
				runPostgresConnTest = true
			case 2:
				runGeneratePassword = true
			case 3:
				runPwnedUsers = true
			case 4:
				runPwnedPassword = true
			default:
				fmt.Println("Invalid Choice, Please Try Again.")
				os.Exit(1)
			}

		default:
			fmt.Println("Invalid Choice, Please Try Again.")
			os.Exit(1)
		}
	}

	var err error
	if c.App.Hostname == "" {
		c.App.Hostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("getting hostname: %w", err)
		}
	}
	if c.MySQL == nil && c.Postgres == nil && !runRds && c.LogParser == nil {
		return nil, fmt.Errorf("Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate it with your dbname,username etc.. before using this utility. For additional details please check github readme.")
	}
	if c.MySQL != nil && c.Postgres != nil && !runRds {
		return nil, fmt.Errorf("Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate either mysql or postgres at a time. For additional details please check github readme.")
	}
	if c.MySQL == nil && runMySql {
		return nil, fmt.Errorf("In older version we used [database] label and in current version we are changing it to [mysql] and kindly update your kshieldconfig file(/etc/klouddbshield/kshieldconfig.toml) - See sample entry in readme.")
	}

	postgresConfigNeeded := runPostgres || c.App.HBASacanner
	if c.Postgres == nil && postgresConfigNeeded {
		return nil, fmt.Errorf("In older version we used [database] label and in current version we are changing it to [postgres] and kindly update your kshieldconfig file(/etc/klouddbshield/kshieldconfig.toml) - See sample entry in readme.")
	}
	if c.MySQL != nil && c.MySQL.User == "" && runMySql {
		fmt.Printf("Enter Your MySQL DB User: ")
		fmt.Scanln(&c.MySQL.User)
	}
	if c.MySQL != nil && c.MySQL.Password == "" && runMySql {
		fmt.Printf("Enter Your DB MySQL Password for %s: ", c.MySQL.User)
		fmt.Scanln(&c.MySQL.Password)
	}

	if c.Postgres != nil && c.Postgres.User == "" && postgresConfigNeeded {
		fmt.Printf("Enter Your Postgres DB User: ")
		fmt.Scanln(&c.Postgres.User)
	}
	if c.Postgres != nil && c.Postgres.Password == "" && postgresConfigNeeded {
		fmt.Printf("Enter Your DB Postgres Password for %s: ", c.Postgres.User)
		fmt.Scanln(&c.Postgres.Password)
	}

	if c.GeneratePassword == nil {
		c.GeneratePassword = &GeneratePassword{
			Length:           20,
			NumberCount:      2,
			NumUppercase:     2,
			SpecialCharCount: 2,
		}
	}

	CONF = c
	return c, nil
}

func loadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigName("kshieldconfig")
	v.AddConfigPath("./")
	v.AddConfigPath("/etc/klouddbshield")

	c := &Config{}

	err := v.ReadInConfig()
	if err != nil {
		return c, fmt.Errorf("fatal error config file: %w", err)
	}
	err = v.Unmarshal(c)
	if err != nil {
		return c, fmt.Errorf("unmarshal: %w", err)
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

func (i *inputReader) Read(msg string) string {
	fmt.Print(msg)
	input, err := i.reader.ReadString('\n')
	if err != nil {
		fmt.Println("Invalid input for logparser:", err)
		os.Exit(1)
	}
	input = strings.TrimSuffix(input, "\n")
	input = strings.Trim(input, `"`)
	input = strings.Trim(input, "'")

	return input
}

func getLogParserInputs() *LogParser {
	fmt.Print(cons.MSG_LogPaserChoise)
	choice := 0
	fmt.Scanln(&choice)
	command := cons.LogParserChoiseMapping[choice]
	if command == "" {
		fmt.Println("Invalid Choice, Please Try Again.")
		os.Exit(1)
	}

	reader := newInputReader()

	prefix := reader.Read("Enter Log Line Prefix: ")
	logfile := reader.Read("Enter Log File Path: ")
	beginTime := reader.Read("Enter Begin Time (format: 2006-01-02 15:04:05) [optional]: ")
	endTime := reader.Read("Enter End Time (format: 2006-01-02 15:04:05) [optional]: ")

	var ipfile string
	if command == cons.LogParserCMD_MismatchIPs {
		ipfile = reader.Read("Enter IP File Path: ")
	}

	var hbaConfigFile string
	if command == cons.LogParserCMD_HBAUnusedLines {
		hbaConfigFile = reader.Read("Enter pg_hba.conf File Path: ")
	}

	l, err := NewLogParser(command, beginTime, endTime, prefix, logfile, ipfile, hbaConfigFile)
	if err != nil {
		fmt.Println("Invalid input for logparser:", err)
		os.Exit(1)
	}

	return l
}

func MustNewConfig() *Config {
	config, err := NewConfig()
	if err != nil {
		fmt.Println("Can't create config")
		fmt.Println(err)
		fmt.Println("Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate it with your dbname,username etc.. before using this utility. For additional details please check github readme.")
		os.Exit(1)
	}

	return config
}
