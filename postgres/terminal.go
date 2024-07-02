package postgres

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/klouddb/klouddbshield/model"
)

func PrintScore(score map[int]*model.Status) {
	if score == nil {
		return
	}

	format := []string{
		"Section 1  - Installation and Patches              - %d/%d    - %.2f%%\n",
		"Section 2  - Directory and File Permissions        - %d/%d    - %.2f%%\n",
		"Section 3  - Logging Monitoring and Auditing       - %d/%d  - %.2f%%\n",
		"Section 4  - User Access and Authorization         - %d/%d    - %.2f%%\n",
		"Section 5  - Connection and Login                  - %d/%d    - %.2f%%\n",
		"Section 6  - Postgres Settings                     - %d/%d    - %.2f%%\n",
		"Section 7  - Replication                           - %d/%d    - %.2f%%\n",
		"Section 8  - Special Configuration Considerations  - %d/%d    - %.2f%%\n",
	}
	for key, value := range format {
		total := (score[key+1].Pass + score[key+1].Fail)
		if total == 0 {
			continue
		}
		fmt.Printf(value,
			score[key+1].Pass,
			(score[key+1].Pass + score[key+1].Fail),
			(float64(score[key+1].Pass) / float64(total) * 100),
		)
	}
	fmt.Printf("Overall Score - %d/%d - %.2f%%\n",
		score[0].Pass,
		(score[0].Pass + score[0].Fail),
		(float64(score[0].Pass) / float64((score[0].Pass + score[0].Fail)) * 100),
	)
}

func PrintSummary(listOfResult []*model.HBAScannerResult) {
	if len(listOfResult) == 0 {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	// hba check 1 - Check Trust In Method" - FAIL
	for _, result := range listOfResult {
		if result.Status == "Pass" {

			t.AppendSeparator()
			color := text.FgGreen
			row := fmt.Sprintf("HBA Check %d - %s", result.Control, result.Title)
			t.AppendRow(table.Row{row, color.Sprintf("%s", result.Status)})

		} else {
			t.AppendSeparator()
			color := text.FgRed
			row := fmt.Sprintf("HBA Check %d - %s", result.Control, result.Title)
			t.AppendRow(table.Row{row, color.Sprintf("%s", result.Status)})
			t.AppendSeparator()

		}
	}
	t.SetStyle(table.StyleLight)
	t.Render()

}

func PrintShortSummary(score map[int]*model.Status, listOfResult []*model.HBAScannerResult, errorMap map[string]error) {
	fmt.Println(text.Bold.Sprint("Postgres Report:"))
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	if err := errorMap["All Postgres checks(Recommended)"]; err != nil {
		fmt.Println("Error from \"All Postgres checks\": ", err)
	} else {

		t.AppendSeparator()

		t.AppendRow(table.Row{
			"Postgres Checks",
			fmt.Sprintf("%d/%d", score[0].Pass, (score[0].Pass + score[0].Fail)),
			fmt.Sprintf("%.2f%%", (float64(score[0].Pass) / float64((score[0].Pass + score[0].Fail)) * 100)),
		})
	}

	if err := errorMap["HBA Scanner"]; err != nil {
		fmt.Println("Error from HBA Scanner: ", err)
	} else {

		passcount := 0
		for _, result := range listOfResult {
			if result.Status == "Pass" {
				passcount++
			}
		}

		t.AppendSeparator()
		t.AppendRow(table.Row{
			"HBA Checks",
			fmt.Sprintf("%d/%d", passcount, len(listOfResult)),
			fmt.Sprintf("%.2f%%", (float64(passcount) / float64(len(listOfResult)) * 100)),
		})
	}

	t.SetStyle(table.StyleLight)
	t.Render()
	fmt.Println("")
}
