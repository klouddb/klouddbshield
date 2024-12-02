package cons

import "fmt"

var (
	ErrFmt = `
		cmd: 	%s
		cmderr: %s
		outerr: %s`
	CMDReturnNothingFmt = "cmd: %s \nreturns nothing"
	ExpectedOutput      = "Expected some output for below command:\n%s"
	ColorReset          = "\033[0m"
	ColorRed            = "\033[31m"
	ColorGreen          = "\033[32m"
)

const (
	MSG_SpacyInstallCommands = `
To install spacy, run below commands

- pip3 install -U pip3 setuptools wheel
- pip3 install -U spacy
- python -m spacy download en_core_web_sm

After installing, run below command to check if spacy is installed properly. for more info about spacy install visit: https://spacy.io/usage`

	// LogParserTitle_MismatchIPs         = "Mismatch IPs"
	LogParserTitle_UniqueIPs           = "Unique IPs"
	LogParserTitle_InactiveUsr         = "Inactive Users"
	LogParserTitle_HBAUnusedLines      = "HBA Unused Lines"
	LogParserTitle_All                 = "All"
	LogParserTitle_PasswordLeakScanner = "Password Leak Scanner"
)

const (
	SelectionIndex_AllCommands = iota + 1
	SelectionIndex_PostgresChecks
	SelectionIndex_HBAScanner
	SelectionIndex_PIIScanner
	SelectionIndex_InactiveUsers
	SelectionIndex_UniqueIPs
	SelectionIndex_HBAUnusedLines
	SelectionIndex_PasswordManager
	SelectionIndex_PasswordLeakScanner
	SelectionIndex_AWSRDS
	SelectionIndex_AWSAurora
	SelectionIndex_MySQL
	SelectionIndex_TransactionWraparound
	// SelectionIndex_CreatePostgresconfig
	// SelectionIndex_ConfigAuditing
	SelectionIndex_SSLCheck
	SelectionIndex_Exit
)

type CommandTitle struct {
	Title, CMD string
}

var CommandList = []CommandTitle{
	{ // 1
		CMD:   RootCMD_All,
		Title: "All Postgres checks(Recommended)",
	},
	{ // 2
		CMD:   RootCMD_PostgresCIS,
		Title: "Postgres CIS and User Security checks",
	},
	{ // 3
		CMD:   RootCMD_HBAScanner,
		Title: "HBA Scanner",
	},
	{ // 4
		CMD:   RootCMD_PiiScanner,
		Title: "Postgres PII report",
	},
	{ // 5
		CMD:   LogParserCMD_InactiveUser,
		Title: "Inactive user report",
	},
	{ // 6
		CMD:   LogParserCMD_UniqueIPs,
		Title: "Client ip report",
	},
	{ // 7
		CMD:   LogParserCMD_HBAUnusedLines,
		Title: "HBA unused lines report",
	},
	{ // 8
		CMD:   RootCMD_PasswordManager,
		Title: "Password Manager",
	},
	{ // 9
		CMD:   LogParserCMD_PasswordLeakScanner,
		Title: "Password leak scanner",
	},
	{ // 10
		CMD:   RootCMD_AWSRDS,
		Title: "AWS RDS Sec Report",
	},
	{ // 11
		CMD:   RootCMD_AWSAurora,
		Title: "AWS Aurora Sec Report",
	},
	{ // 12
		CMD:   RootCMD_MySQL,
		Title: "MySQL Report",
	},
	{ // 13
		CMD:   RootCMD_TransactionWraparound,
		Title: "Transaction Wraparound Report",
	},
	{ // 14
		CMD:   RootCMD_SSLCheck,
		Title: "SSL Check",
	},
	{ // 15
		CMD:   RootCMD_Exit,
		Title: "Exit",
	},
}

var MSG_Choise = func() string {
	out := ""
	for i, v := range CommandList {
		out += fmt.Sprintf("%2d: %s\n", i+1, v.Title)
	}

	return fmt.Sprintf("%v\nEnter your choice to execute(from 1 to %d):", out, len(CommandList))
}()

var MSG_ChoiseCustomTemplate = func() string {
	out := ""
	for i, v := range CommandList {
		out += fmt.Sprintf("%2d: %s\n", i+1, v.Title)
		if i == 1 {
			break
		}
	}

	return fmt.Sprintf("%v\nEnter your choice to execute(from 1 or 2):", out)
}()

const (
	RootCMD_All                   = "all"
	RootCMD_PostgresCIS           = "postgres_cis"
	RootCMD_HBAScanner            = "hba_scanner"
	RootCMD_PasswordManager       = "password_manager"
	RootCMD_CompareConfig         = "compare_config"
	RootCMD_AWSRDS                = "aws_rds"
	RootCMD_AWSAurora             = "aws_aurora"
	RootCMD_MySQL                 = "mysql"
	RootCMD_PiiScanner            = "pii_scanner"
	RootCMD_TransactionWraparound = "transaction_wraparound"
	RootCMD_CreatePostgresconfig  = "create_postgresconfig"
	RootCMD_ConfigAuditing        = "config_auditing"
	RootCMD_SSLCheck              = "ssl_check"
	RootCMD_Exit                  = "exit"

	// LogParserCMD_MismatchIPs         = "mismatch_ips"
	LogParserCMD_UniqueIPs           = "unique_ip"
	LogParserCMD_InactiveUser        = "inactive_users"
	LogParserCMD_HBAUnusedLines      = "unused_lines"
	LogParserCMD_SqlInjectionScan    = "sql_injection_scan"
	LogParserCMD_All                 = "all"
	LogParserCMD_PasswordLeakScanner = "password_leak_scanner"
	// _LogParserCMD_QueryParser        = "pii_query_parser"

	PasswordManager_CommonUsers = "common_users"
)

var LogParserChoiseMapping = map[int]string{
	// 1: LogParserCMD_MismatchIPs,
	1: LogParserCMD_InactiveUser,
	2: LogParserCMD_UniqueIPs,
	3: LogParserCMD_HBAUnusedLines,
	// 4: LogParserCMD_QueryParser,
	4: LogParserCMD_PasswordLeakScanner,
	5: LogParserCMD_All,
}
