package piiscanner

import (
	"io"

	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

func (c Config) outputOptions() dpdpa.OutputOptions {
	return dpdpa.OutputOptions{
		PrintAllResults:  c.printAllResults,
		PrintSummaryOnly: c.PrintSummaryOnly,
	}
}

// PrintTerminalOutput prints scan results using DPDPA's shared output helper.
func PrintTerminalOutput(i *DatabasePIIScanOutput, cnf Config) {
	dpdpa.PrintTerminalOutput(i, cnf.outputOptions())
}

// CreateTabularOutputfile writes confidence log files using DPDPA's shared helper
// into the current working directory (shield CLI convention).
func CreateTabularOutputfile(i *DatabasePIIScanOutput, cnf Config) {
	dpdpa.CreateTabularOutputfile(i, cnf.outputOptions(), ".")
}

// GenerateTabularOutput renders tabular output using DPDPA's shared helper.
func GenerateTabularOutput(w io.Writer, i *DatabasePIIScanOutput, cnf Config, filePrint string) {
	dpdpa.GenerateTabularOutput(w, i, cnf.outputOptions(), filePrint)
}
