package simpletextreport

import (
	"bytes"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/olekukonko/tablewriter"
)

func PrintReportInFile(listOfResults []*model.Result, database, title string) string {
	buf := new(bytes.Buffer)

	out := title + "\n"
	table := tablewriter.NewWriter(buf)

	for _, result := range listOfResults {
		table.Append([]string{
			result.Control,
			strings.ReplaceAll(result.Title, "\t", " "),
			strings.ReplaceAll(result.Description, "\t", " "),
			result.Status,
		})
		if result.Status == "Fail" {
			table.Append([]string{
				result.Control,
				strings.ReplaceAll(result.Title, "\t", " "),
				strings.ReplaceAll(result.Description, "\t", " "),
				"Reason: " + strings.ReplaceAll(result.FailReason, "\t", " "),
			})
		}
	}

	table.SetAutoMergeCellsByColumnIndex([]int{0, 1, 2})
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.Render()

	if database != "" {
		out += "Postgres Version :" + database
	}

	return out + "\n\n" + buf.String()
}

func PrintHBAReportInFile(listOfResults []*model.HBAScannerResult) string {
	buf := new(bytes.Buffer)

	table := tablewriter.NewWriter(buf)

	for _, result := range listOfResults {
		table.Append([]string{
			strings.ReplaceAll(result.Title, "\t", " "),
			strings.ReplaceAll(result.Description, "\t", " "),
			result.Status,
		})
		if result.Status == "Fail" {
			table.Append([]string{
				strings.ReplaceAll(result.Title, "\t", " "),
				strings.ReplaceAll(result.Description, "\t", " "),
				result.FailRowsInString,
			})
		}
	}

	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.Render()

	return buf.String()
}
