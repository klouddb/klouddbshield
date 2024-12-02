package logparser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/logger"
	"github.com/klouddb/klouddbshield/pkg/runner"
	"github.com/olekukonko/tablewriter"
)

func PrintErrorBox(t string, err error) {
	fmt.Printf("> %s: %s\n", t, err)
}

func PrintTerminalResultsForLogParser(ctx context.Context, runners []runner.Parser, outputType string) {
	for _, r := range runners {
		switch r := r.(type) {
		case *ErrorHelper:
			PrintErrorBox(r.Status, fmt.Errorf("Error in %s: %s", r.Command, r.Message))
		case *UnusedHBALineHelper:
			unusedLine := r.GetResult(ctx)
			if len(unusedLine) == 0 {
				fmt.Println("\nNo unused lines found from given log file please check the file or errors in " + logger.GetLogFileName())
				continue
			}

			if outputType == "json" {
				fmt.Println("")
				lines := []int{}
				for _, l := range unusedLine {
					lines = append(lines, l.LineNo)
				}
				fmt.Println("Unused lines found from given log file:", lines)
				fmt.Println("")
				continue
			}

			fmt.Println("")
			fmt.Println("Unused lines found from given log file:")
			for _, line := range unusedLine {
				fmt.Printf("\tLine No. %d \t:\t%s\n", line.LineNo, line.Line)
			}
			fmt.Println("")
		case *UniqueIPHelper:
			ips := r.GetResult(ctx)
			if len(ips) == 0 {
				fmt.Println("\nNo unique IPs found from given log file please check the file or errors in " + logger.GetLogFileName())
				continue
			}

			fmt.Println("\nUnique IPs found from given log file:")

			if outputType == "json" {
				out, _ := json.MarshalIndent(ips, "", "\t")
				fmt.Println(string(out))
				continue
			}

			for _, ip := range ips {
				fmt.Println("\t" + ip)
			}
		case *InactiveUsersHelper:
			userdata := r.GetResult(ctx)
			if len(userdata) == 0 || len(userdata[1]) == 0 {
				fmt.Println("No users found in log file. please check the log file or errors in " + logger.GetLogFileName())
				continue
			}

			// userdata[0] contains users from database
			// userdata[1] contains users from log file
			// userdata[2] contains inactive users from database

			if outputType == "json" {
				out, _ := json.MarshalIndent(userdata, "", "\t")
				fmt.Println(string(out))
				continue
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
		case *PasswordLeakHelper:
			leakedPasswords := r.GetResult(ctx)
			if len(leakedPasswords) == 0 {
				fmt.Println("No leaked passwords found in log file. please check the log file or errors in " + logger.GetLogFileName())
				continue
			}

			if outputType == "json" {
				sort.SliceStable(leakedPasswords, func(i, j int) bool {
					return leakedPasswords[i].Query < leakedPasswords[j].Query
				})
				out, _ := json.MarshalIndent(leakedPasswords, "", "\t")
				fmt.Println(string(out))
				continue
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Password", "Query"})
			for _, password := range leakedPasswords {
				table.Append([]string{password.Password, password.Query})
			}

			table.SetRowLine(true)
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetAutoWrapText(false)
			table.Render()
		case *QueryParseHelper:
			fmt.Println("PII data found in the query log file")
			queries := r.GetResult(ctx)
			if len(queries) == 0 {
				fmt.Println("No PII data found in log file")
				continue
			}

			if outputType == "json" {
				out, _ := json.MarshalIndent(queries, "", "\t")
				fmt.Println(string(out))
				continue
			}

			for label, v := range queries {
				fmt.Println("label: ", label)
				for _, queryData := range v {
					fmt.Println("\t Column:", queryData.Col, "\t Value:", queryData.Val)
				}
			}

			fmt.Println("Successfully parsed them log file")
		case *SQLInjectionHelper:
			queries := r.GetResult(ctx)
			if len(queries) == 0 {
				fmt.Println("No SQL Injection related logs found in log file")
				continue
			}

			if outputType == "json" {
				sort.SliceStable(queries, func(i, j int) bool {
					return queries[i] < queries[j]
				})
				out, _ := json.MarshalIndent(queries, "", "\t")
				fmt.Println(string(out))
				continue
			}

			fmt.Println("SQL Injection related logs found in log file")
			for _, queryData := range queries {
				fmt.Println("> ", queryData)
			}
			fmt.Println()
		}
	}
}

func PrintFastRunnerReport(logParserCnf *config.LogParser, fastRunnerResp *runner.FastRunnerResponse) {
	PrintFileParsingError(fastRunnerResp.FileErrors)

	if fastRunnerResp.TotalLines == 0 {
		fmt.Printf("No log lines found in the log file(s).. Please see error log %s  for additional information\n", logger.GetLogFileName())
		return
	}

	for i, successLines := range fastRunnerResp.SuccessLines {
		command := logParserCnf.Commands[i]

		perc := float64(successLines) * 100 / float64(fastRunnerResp.TotalLines)
		switch perc {
		case 100:
			// added extra space to overrider the previous line proprely
			fmt.Println(command + " ::: Successfully parsed all files                                                                 ")
		case 0:
			fmt.Printf(command+" ::: Was not able to parse logfile(s).. Please see error log %s  for additional information\n", logger.GetLogFileName())
		default:
			fmt.Printf(command+" ::: Was able to partially (%d/%d=%f) parse the logfile(s).. Please see error log %s  for additional information\n", successLines, fastRunnerResp.TotalLines, perc, logger.GetLogFileName())
		}
	}

	fmt.Printf("Parsed %d files which took: %s\n", len(logParserCnf.LogFiles), time.Since(fastRunnerResp.StartTime))

}

func PrintSummary(ctx context.Context, runners []runner.Parser, logParserCnf *config.LogParser,
	fastRunnerResp *runner.FastRunnerResponse, fileData map[string]interface{}, outputType string) {

	PrintFileParsingError(fastRunnerResp.FileErrors)

	data := [][]string{}
	allValues := []interface{}{}
	for i, cmd := range logParserCnf.Commands {
		parseStatus := "All lines parsed successfully"
		if fastRunnerResp.SuccessLines[i] == 0 {
			parseStatus = "No lines parsed successfully"
		} else if fastRunnerResp.SuccessLines[i] != fastRunnerResp.TotalLines {
			parseStatus = fmt.Sprintf("%.2f%% lines parsed successfully", float64(fastRunnerResp.SuccessLines[i])*100/float64(fastRunnerResp.TotalLines))
		}

		resultMsg := "No result found"
		var val interface{}
		switch r := runners[i].(type) {
		case *ErrorHelper:
			resultMsg = r.Message
		case *UnusedHBALineHelper:
			unusedLine := r.GetResult(ctx)
			if len(unusedLine) == 0 {
				resultMsg = "No unused lines found in hba_conf file"
			} else {
				resultMsg = fmt.Sprintf("%d unused lines found in hba_conf file\n", len(unusedLine))
			}
			val = unusedLine

		case *UniqueIPHelper:
			ips := r.GetResult(ctx)
			if len(ips) == 0 {
				resultMsg = "No IPs found from log file"
			} else {
				resultMsg = fmt.Sprintf("%d unique IPs found from log file\n", len(ips))
			}
			val = ips

		case *InactiveUsersHelper:
			userdata := r.GetResult(ctx)
			if len(userdata) == 0 {
				resultMsg = "Some issue with result"
			} else if len(userdata[1]) == 0 {
				resultMsg = "No users found from log file."
			} else if len(userdata[0]) == 0 {
				resultMsg = "No users found from database."
			} else {
				if len(userdata[2]) == 0 {
					resultMsg = "No inactive users in database"
				} else {
					resultMsg = fmt.Sprintf("%d inactive users found in database\n", len(userdata[2]))
				}
			}
			val = userdata

		case *PasswordLeakHelper:
			leakedPasswords := r.GetResult(ctx)
			if len(leakedPasswords) == 0 {
				resultMsg = "No leaked passwords found."
			} else {
				resultMsg = fmt.Sprintf("%d leaked passwords found\n", len(leakedPasswords))
			}
			val = leakedPasswords

		case *SQLInjectionHelper:
			sqlInjection := r.GetResult(ctx)
			if len(sqlInjection) == 0 {
				resultMsg = "No SQL Injection related logs found in log file."
			} else {
				resultMsg = fmt.Sprintf("%d SQL Injection related logs found in log file\n", len(sqlInjection))
			}
			val = sqlInjection
		}

		data = append(data, []string{cmd, parseStatus, resultMsg})
		allValues = append(allValues, map[string]interface{}{
			"Command":      cmd,
			"Parse Status": parseStatus,
			"Result":       resultMsg,
			"Value":        val,
		})
	}

	data = append(data, []string{
		fmt.Sprintf("Parsed %d files which took: %s", len(logParserCnf.LogFiles), time.Since(fastRunnerResp.StartTime)),
		"",
		"",
	})
	allValues = append(allValues, fmt.Sprintf("Parsed %d files which took: %s", len(logParserCnf.LogFiles), time.Since(fastRunnerResp.StartTime)))

	var buffer bytes.Buffer

	mult := io.MultiWriter(&buffer, os.Stdout)

	if outputType == "json" {
		fileData["Log Parser Summary"] = allValues

		jsonData, err := json.MarshalIndent(fileData, "", "    ")
		if err != nil {
			fmt.Println("Error while marshalling data to json")
			return
		}
		fmt.Println(string(jsonData))
		return
	}
	table := tablewriter.NewWriter(mult)
	for _, v := range data {
		table.Append(v)
	}

	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.Render()
	fmt.Println("")

	fileData["Log Parser Summary"] = buffer.String()
}

func PrintFileParsingError(fileError map[string]string) {
	if len(fileError) == 0 {
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Filename", "Error"})

	for filename, err := range fileError {
		table.Append([]string{filename, err})
	}

	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.Render()
	if len(fileError) > 0 {
		fmt.Println("> " + text.FgHiRed.Sprint("Please check the log file for more information >>>"+logger.GetLogFileName()))
	}

	fmt.Println("")
}
