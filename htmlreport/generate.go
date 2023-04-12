package htmlreport

import (
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

func GenerateHTMLReport(listOfResults []*model.Result, database string) string {
	populateTable := ""

	for _, result := range listOfResults {

		if result.Status == "Fail" {

			populateTable += fmt.Sprintf(tableTemplate,
				result.Control+" "+result.Title,
				cross,
				strings.ReplaceAll(result.Description, "\n", "</br>"),
				fmt.Sprintf(failReason, strings.ReplaceAll(utils.GetFailReasonInString(result.FailReason), "\n", "</br>")),
				strings.ReplaceAll(result.Rationale, "\n", "</br>"),
				strings.ReplaceAll(result.Procedure, "\n", "</br>"),
				strings.ReplaceAll(result.References, "\n", "</br>"),
			)
		} else {
			populateTable += fmt.Sprintf(tableTemplate,
				result.Control+" "+result.Title,
				tick,
				strings.ReplaceAll(result.Description, "\n", "</br>"),
				"",
				strings.ReplaceAll(result.Rationale, "\n", "</br>"),
				strings.ReplaceAll(result.Procedure, "\n", "</br>"),
				strings.ReplaceAll(result.References, "\n", "</br>"),
			)
		}

	}

	return fmt.Sprintf(body, database+" CIS Report", populateTable)
}
func GenerateHTMLReportForHBA(listOfResults []*model.HBAScannerResult) string {
	populateTable := ""
	populateFailedRowsTable := ""
	hbaFailRowsBodyTemplatedata := ""
	for _, result := range listOfResults {

		if result.Status == "Fail" {
			// populateFailedRowsTable += fmt.Sprintf(hbaFailRowsTemplate,
			populateFailedRowsTable = ""
			for _, row := range result.FailRows {
				populateFailedRowsTable += fmt.Sprintf(hbaFailRowsTemplate, "", row)
			}
			headline := fmt.Sprintf("HBA Check %d - %s (Failure Report)", result.Control, result.Description)
			hbaFailRowsBodyTemplatedata += fmt.Sprintf(hbaFailRowsBodyTemplate, headline, populateFailedRowsTable)

			// strings.ReplaceAll(result.Description, "\n", "</br>"),
			//	fmt.Sprintf(hbafailReason, strings.ReplaceAll(result.FailRowsInString, "\n", "</br>")),

			// strings.ReplaceAll(result.Procedure, "\n", "</br>"),
			// )
			populateTable += fmt.Sprintf(hsbtabletemplate,
				fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description),
				cross,
				result.Description,
				result.FailRowsInString,

				result.Procedure,
			)
		} else {

			populateTable += fmt.Sprintf(hsbtabletemplate,
				fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description),
				tick,
				result.Description,
				"",

				result.Procedure,
			)
		}

	}
	return fmt.Sprintf(body, "HBA Scanner Report", populateTable, hbaFailRowsBodyTemplatedata)
}

// | left foo      | right foo ffffffffffffffffff  <br>wwewffff<br>wwew<br>wwew|
func GenerateMarkdown(listOfResults []*model.Result) string {
	markdown := `
| Left columns  | Right columns |
| ------------- |-------------|
`

	for _, result := range listOfResults {
		row := ""
		row = fmt.Sprintf("| %s | **Description**<br>%s<br><br>**Rationale**<br>%s<br><br>**Procedure**<br>%s<br><br>**References**<br>%s |\n",
			result.Control+" "+result.Title,
			strings.ReplaceAll(result.Description, "\n", "<br>"),
			strings.ReplaceAll(result.Rationale, "\n", "<br>"),
			strings.ReplaceAll(strings.ReplaceAll(result.Procedure, "\n", "<br>"), "|", "\\|"),
			strings.ReplaceAll(result.References, "\n", "<br>"),
		)
		markdown += row

	}
	return markdown
}
