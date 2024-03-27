package cons

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
	MSG_Choise = `
1. Postgres
2. MySQL
3. AWS RDS
4. HBA Scanner
5. Log Parser
6. Password Manager

Enter your choice to execute(1/2/3/4/5/6):`

	MSG_LogPaserChoise = `
1. Inactive Users
2. Unique IPs

Enter your choice to execute(1/2/3):`
)

const (
	LogParserCMD_MismatchIPs = "mismatch_ips"
	LogParserCMD_UniqueIPs   = "unique_ip"
	LogParserCMD_InactiveUsr = "inactive_users"
)

var (
	LogParserChoiseMapping = map[int]string{
		// 1: LogParserCMD_MismatchIPs,
		1: LogParserCMD_InactiveUsr,
		2: LogParserCMD_UniqueIPs,
	}
)
