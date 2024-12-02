package postgres

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// PrintSSLAuditSummary prints the SSL audit results in a table format
func PrintSSLAuditSummary(results *model.SSLScanResult) {
	if results == nil || len(results.Cells) == 0 {
		return
	}

	fmt.Println(text.Bold.Sprint("\nSSL Audit Report:"))
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	t.AppendHeader(table.Row{"Check", "Status", "Details"})

	passCount := 0
	for _, result := range results.Cells {
		status := result.Status
		if status == "Pass" {
			passCount++
			t.AppendRow(table.Row{
				result.Title,
				text.FgGreen.Sprint(status),
				"-",
			})
		} else {
			details := "-"
			if len(result.Message) > 0 {
				details = result.Message
			}

			statusColor := text.FgHiRed
			if status == "Warning" {
				statusColor = text.FgYellow
			}

			t.AppendRow(table.Row{
				result.Title,
				statusColor.Sprint(status),
				utils.WordWrap(details, 30),
			})
		}
		t.AppendSeparator()
	}

	// Add summary row
	t.AppendSeparator()
	t.AppendRow(table.Row{
		"Overall Status",
		fmt.Sprintf("%d/%d Passed", passCount, len(results.Cells)),
		fmt.Sprintf("%.2f%%", (float64(passCount)/float64(len(results.Cells)))*100),
	})

	t.SetStyle(table.StyleLight)
	t.Render()
	fmt.Println()
}

// PrintConfigAuditSummary prints the config audit results in a table format
func PrintConfigAuditSummary(results []*model.ConfigAuditResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println(text.Bold.Sprint("\nConfiguration Audit Report:"))
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	t.AppendHeader(table.Row{"Check", "Status", "Details"})

	passCount := 0
	for _, result := range results {
		status := result.Status
		if status == "Pass" {
			passCount++
			t.AppendRow(table.Row{
				result.Name,
				text.FgGreen.Sprint(status),
				"-",
			})
		} else {
			details := "-"
			if result.FailReason != "" {
				details = result.FailReason
			}

			statusColor := text.FgHiRed
			if status == "Warning" {
				statusColor = text.FgYellow
			}

			t.AppendRow(table.Row{
				result.Name,
				statusColor.Sprint(status),
				details,
			})
		}
		t.AppendSeparator()
	}

	// Add summary row
	t.AppendSeparator()
	t.AppendRow(table.Row{
		"Overall Status",
		fmt.Sprintf("%d/%d Passed", passCount, len(results)),
		fmt.Sprintf("%.2f%%", (float64(passCount)/float64(len(results)))*100),
	})

	t.SetStyle(table.StyleLight)
	t.Render()
	fmt.Println()
}
