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
