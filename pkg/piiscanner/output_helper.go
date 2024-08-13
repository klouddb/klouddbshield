package piiscanner

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/olekukonko/tablewriter"
)

func PrintTerminalOutput(i *DatabasePIIScanOutput, cnf Config) {
	if i == nil || len(i.Data) == 0 {
		fmt.Println("> No PII data found in database")
		return
	}

	if cnf.PrintSummaryOnly {
		printTerminalOutputSimple(i)
	} else {
		printTerminalOutputTable(i, cnf)
	}

}

func printTerminalOutputTable(i *DatabasePIIScanOutput, cnf Config) {
	GenerateTabularOutput(os.Stdout, i, cnf, "")
}

func CreateTabularOutputfile(i *DatabasePIIScanOutput, cnf Config) {
	if i == nil || len(i.Data) == 0 {
		return
	}

	highConfidenceFile, err := os.Create("kshield_pii_highconfidence.log")
	if err != nil {
		fmt.Println("Error creating high confidence log file: ", text.FgRed.Sprint(err))
		return
	}
	defer highConfidenceFile.Close()

	lowConfidenceFile, err := os.Create("kshield_pii_lowconfidence.log")
	if err != nil {
		fmt.Println("Error creating low confidence log file: ", text.FgRed.Sprint(err))
		return
	}
	defer lowConfidenceFile.Close()

	GenerateTabularOutput(highConfidenceFile, i, cnf, "High")
	GenerateTabularOutput(lowConfidenceFile, i, cnf, "Medium|Low")

	lowConfidenceFilePath, _ := filepath.Abs(lowConfidenceFile.Name())
	HighConfidenceFilePath, _ := filepath.Abs(highConfidenceFile.Name())

	fmt.Println("> High confidence log file created at: [ " + HighConfidenceFilePath + " ]")
	fmt.Println("> Low confidence log file created at: [ " + lowConfidenceFilePath + " ]")
}

func GenerateTabularOutput(w io.Writer, i *DatabasePIIScanOutput, cnf Config, filePrint string) {
	columnTable := tablewriter.NewWriter(w)
	headers := []string{"Table", "Column", "Label", "Confidence"}
	columnTable.SetHeader(headers)

	valueTable := tablewriter.NewWriter(w)
	headers = []string{"Table", "Column", "Label", "Confidence", "Detector", "Matched"}
	valueTable.SetHeader(headers)

	var renderValueTable, renderColumnTable bool
	tablesWithPIIData := utils.NewSet[string]()
	tableShowingInTopTable := utils.NewSet[string]()
	for tablename, columns := range i.Data {
		for columnName, piidatas := range columns {
			for _, piidata := range piidatas {
				tablesWithPIIData.Add(tablename)
				if filePrint == "" && !cnf.printAllResults && piidata.Confidence != "High" {
					break
				} else if filePrint != "" && !strings.Contains(filePrint, piidata.Confidence) {
					continue
				}

				data := []string{tablename, columnName, string(piidata.Label), piidata.Confidence + " " + piidata.ConfidenceIcon}

				currentTable := columnTable
				if piidata.DetectorType == DetectorType_ValueDetector {
					data = append(data, piidata.DetectorName, fmt.Sprintf("%d/%d", piidata.MatchedCount, piidata.ScanedValueCount))
					currentTable = valueTable
				}

				currentTable.Append(data)
				renderColumnTable = renderColumnTable || piidata.DetectorType == DetectorType_ColumnDetector
				renderValueTable = renderValueTable || piidata.DetectorType == DetectorType_ValueDetector

				tableShowingInTopTable.Add(tablename)

				if filePrint == "" && !cnf.printAllResults {
					break
				}
			}
		}
	}

	if renderValueTable {
		msg := "Data Scan Report"
		if filePrint == "" {
			msg = text.Bold.Sprint(msg)
		}
		fmt.Fprintln(w, msg)
		valueTable.SetAutoMergeCellsByColumnIndex([]int{0, 1})
		valueTable.SetRowLine(true)
		valueTable.SetAlignment(tablewriter.ALIGN_LEFT)
		valueTable.SetAutoWrapText(false)
		valueTable.Render()
	}

	if renderColumnTable {
		msg := "Meta Scan Report"
		if filePrint == "" {
			msg = text.Bold.Sprint(msg)
		}

		fmt.Fprintln(w, msg)
		columnTable.SetAutoMergeCellsByColumnIndex([]int{0, 1})
		columnTable.SetRowLine(true)
		columnTable.SetAlignment(tablewriter.ALIGN_LEFT)
		columnTable.SetAutoWrapText(false)
		columnTable.Render()
	}

	if filePrint != "" {
		return
	}

	switch {
	case tableShowingInTopTable.Len() == 0 && tablesWithPIIData.Len() == 0:
		fmt.Fprintln(w, "> No PII data found in database")

	case tableShowingInTopTable.Len() == 0 && tablesWithPIIData.Len() != 0:
		fmt.Fprintln(w, "> We have displayed only high-confidence entities in the list above. In addition to these PII entities, we also identified some low-confidence entities in the following tables:")
		fmt.Fprintln(w, text.FgHiRed.Sprint(utils.AraryToHumanReadableString(tablesWithPIIData.Slice())))
		fmt.Fprintln(w, "Please check detailed log file or html file for additional data")

	case tableShowingInTopTable.Len() != 0 && tablesWithPIIData.Len() != 0 && tableShowingInTopTable.Len() == tablesWithPIIData.Len():
		if cnf.printAllResults {
			fmt.Fprintln(w, "> We have displayed only high-confidence entities in the list above.")
		} else {
			fmt.Fprintln(w, "> We have displayed only high-confidence entities in the list above. In addition to these PII entities, we also identified some low-confidence entities.")
			fmt.Fprintln(w, "Please check detailed log file or html file for additional data.")

		}

	case tableShowingInTopTable.Len() != 0 && tablesWithPIIData.Len() != 0 && tableShowingInTopTable.Len() != tablesWithPIIData.Len():
		fmt.Fprintln(w, "> We have displayed only high-confidence entities in the list above. In addition to these PII entities, we also identified some low-confidence entities in the following tables:")
		fmt.Fprintln(w, text.FgHiRed.Sprint(utils.AraryToHumanReadableString(tablesWithPIIData.Slice())))
		fmt.Fprintln(w, "Please check detailed log file or html file for additional data.")
	}

	fmt.Fprintln(w, "")
}

func printTerminalOutputSimple(i *DatabasePIIScanOutput) {
	if i == nil || len(i.Data) == 0 {
		fmt.Println("> No PII data found in database")
		return
	}

	// var renderValueTable, renderColumnTable bool
	m := map[string] /* table name */ map[string] /* confidence */ map[string] /* detector */ []string{}
	for tablename, columns := range i.Data {
		m[tablename] = map[string]map[string][]string{}
		for columnName, piidatas := range columns {
			for _, piidata := range piidatas {
				if _, ok := m[tablename][piidata.Confidence]; !ok {
					m[tablename][piidata.Confidence] = map[string][]string{}
				}

				if _, ok := m[tablename][piidata.Confidence][string(piidata.DetectorType)]; !ok {
					m[tablename][piidata.Confidence][string(piidata.DetectorType)] = []string{}
				}

				m[tablename][piidata.Confidence][string(piidata.DetectorType)] = append(m[tablename][piidata.Confidence][string(piidata.DetectorType)],
					fmt.Sprintf("%s as %s", columnName, piidata.Label))
			}
		}
	}

	fmt.Println()
	headerPrinted := false
	// print all tables with high confidence
	for tablename, confidences := range m {
		if _, ok := confidences["High"]; ok {
			if !headerPrinted {
				fmt.Println("Tables with high confidence PII data:")
				headerPrinted = true
			}
			fmt.Printf("%s \n", text.FgHiRed.Sprint(tablename))
			for detector, columns := range confidences["High"] {
				// fmt.Printf("-> %s (%d column): \n    - %s\n", detector, len(columns), strings.Join(columns, "\n    - "))
				fmt.Printf("-> %s (%d column): %s\n", detector, len(columns), utils.AraryToHumanReadableString(columns))
			}
		}
	}
	fmt.Println()

	lowConfidenceTables := []string{}
	totalTables := 0
	for tablename, confidences := range m {
		if len(confidences) != 0 {
			totalTables++
		}
		addTable := true
		var columns int
		for v := range confidences {
			if v == "High" {
				addTable = false
				break
			}
			for _, c := range confidences[v] {
				columns += len(c)
			}
		}

		if addTable && columns > 0 {
			tablename = text.FgHiBlue.Sprintf("%s (%d column)", tablename, columns)
			lowConfidenceTables = append(lowConfidenceTables, tablename)
		}
	}

	if len(lowConfidenceTables) > 0 {
		tables := strings.Join(lowConfidenceTables, "\n-> ")
		// tables = text.FgHiRed.Sprint(tables)
		fmt.Printf("There are total %s tables with pii data in your database. here are some with low confidence: \n-> %s\n",
			text.FgHiRed.Sprint(totalTables), tables)
		fmt.Println()
	}

	fmt.Println("For more details, please use the detailed output option")
}

func GenerateOutputFile(i *DatabasePIIScanOutput) (string, error) {
	if i == nil || len(i.Data) == 0 {
		return "", nil
	}

	// remove this before release
	f, err := os.Create("output.csv")
	if err != nil {
		return "", fmt.Errorf("error creating output file: %v", err)
	}
	csvFile := csv.NewWriter(f)

	for tablename, columns := range i.Data {
		for columnName, piidatas := range columns {
			for _, piidata := range piidatas {

				data := []string{tablename, columnName, string(piidata.Label), piidata.Confidence}

				if piidata.DetectorType == DetectorType_ValueDetector {
					data = append(data, piidata.DetectorName, fmt.Sprintf("%d/%d", piidata.MatchedCount, piidata.ScanedValueCount))
				}

				if err := csvFile.Write(data); err != nil {
					return "", fmt.Errorf("error writing to output file: %v", err)
				}
			}
		}
	}

	csvFile.Flush()

	if err := csvFile.Error(); err != nil {
		return "", fmt.Errorf("error flushing output file: %v", err)
	}

	fileAbsPath, _ := filepath.Abs(f.Name())

	return fileAbsPath, nil
}
