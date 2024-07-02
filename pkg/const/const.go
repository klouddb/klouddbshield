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
	// LogParserTitle_MismatchIPs         = "Mismatch IPs"
	LogParserTitle_UniqueIPs           = "Unique IPs"
	LogParserTitle_InactiveUsr         = "Inactive Users"
	LogParserTitle_HBAUnusedLines      = "HBA Unused Lines"
	LogParserTitle_All                 = "All"
	LogParserTitle_PasswordLeakScanner = "Password Leak Scanner"
)

var CommandList = []string{
	"All Postgres checks(Recommended)",
	"Postgres CIS and User Security checks",
	"HBA Scanner",
	"Inactive user report",
	"Client ip report",
	"HBA unused lines report",
	"Password Manager",
	"Password leak scanner",
	"AWS RDS Sec Report",
	"AWS Aurora Sec Report",
	"MySQL Report",
	"Exit",
}

var MSG_Choise = func() string {
	out := ""
	for i, v := range CommandList {
		out += fmt.Sprintf("%2d: %s\n", i+1, v)
	}

	return out + "\nEnter your choice to execute(from 1 to 12):"
}()

const (
	// LogParserCMD_MismatchIPs         = "mismatch_ips"
	LogParserCMD_UniqueIPs           = "unique_ip"
	LogParserCMD_InactiveUsr         = "inactive_users"
	LogParserCMD_HBAUnusedLines      = "unused_lines"
	LogParserCMD_All                 = "all"
	LogParserCMD_PasswordLeakScanner = "password_leak_scanner"
)

var (
	LogParserChoiseMapping = map[int]string{
		// 1: LogParserCMD_MismatchIPs,
		1: LogParserCMD_InactiveUsr,
		2: LogParserCMD_UniqueIPs,
		3: LogParserCMD_HBAUnusedLines,
		4: LogParserCMD_PasswordLeakScanner,
		5: LogParserCMD_All,
	}
)
