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

	return fmt.Sprintf(body, database, populateTable)
}
