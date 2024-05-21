package htmlreport

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

var (
	//go:embed template/main.tmpl
	mainTemplate string
	tmpl         = template.Must(template.New("main.tmpl").Parse(mainTemplate))
)

// Render generates the HTML report file with the provided filename and permission.
func (h *HTMLHelper) Render(filename string, perm fs.FileMode) (bool, error) {
	if h == nil || len(h.tabs) == 0 {
		return false, nil
	}

	tabLink := bytes.NewBuffer(nil)
	tabContent := bytes.NewBuffer(nil)
	html := bytes.NewBuffer(nil)

	for i, tab := range h.tabs {
		class := ""
		if i == 0 {
			class = "active"
		}

		tmpl.ExecuteTemplate(tabLink, "tabLink", map[string]interface{}{
			"Class": class,
			"Href":  strings.ReplaceAll(tab.name, " ", ""),
			"Name":  tab.name,
		})

		tmpl.ExecuteTemplate(tabContent, "tabContent", map[string]interface{}{
			"Id":    strings.ReplaceAll(tab.name, " ", ""),
			"Class": class,
			"Body":  template.HTML(tab.body),
		})

	}

	tmpl.ExecuteTemplate(html, "html", map[string]interface{}{
		"TabLink":    template.HTML(tabLink.String()),
		"TabContent": template.HTML(tabContent.String()),
	})

	// Write HTML to file
	return true, os.WriteFile(filename, html.Bytes(), perm)

}

// Renders the HTML Template for the Postgres Security Report
func RenderHTMLTemplate(listOfResults []*model.Result, scoreMap map[int]*model.Status, database string) string {
	body := bytes.NewBuffer(nil)
	tableTemplate := bytes.NewBuffer(nil)
	tos := bytes.NewBuffer(nil)
	dataTables := bytes.NewBuffer(nil)
	sectionProgressBars := bytes.NewBuffer(nil)
	overallProgressBar := bytes.NewBuffer(nil)

	// Define sections statically for demonstration
	sections := []*model.Section{
		{Name: "Overall Score", Score: 0, MaxScore: 0, Color: "#373854"},
		{Name: "Section 1  - Installation and Patches", Score: 0, MaxScore: 0, Color: "#EA4335"},
		{Name: "Section 2  - Directory and File Permissions", Score: 0, MaxScore: 0, Color: "#FBBC05"},
		{Name: "Section 3  - Logging Monitoring and Auditing", Score: 0, MaxScore: 0, Color: "#34A853"},
		{Name: "Section 4  - User Access and Authorization", Score: 0, MaxScore: 0, Color: "#673AB7"},
		{Name: "Section 5  - Connection and Login", Score: 0, MaxScore: 0, Color: "#4285F4"},
		{Name: "Section 6  - Postgres Settings", Score: 0, MaxScore: 0, Color: "#9E379F"},
		{Name: "Section 7  - Replication", Score: 0, MaxScore: 0, Color: "#7BB3FF"},
		{Name: "Section 8  - Special Configuration Considerations", Score: 0, MaxScore: 0, Color: "#FF6F69"},
	}

	overallSection := sections[0]
	overallSection.Score = scoreMap[0].Pass
	overallSection.MaxScore = scoreMap[0].Pass + scoreMap[0].Fail

	// Find the first control in each section and it's id
	sectionLeaderMap := make(map[int]string)
	for i := 1; i < 9; i++ {
		sectionLeaderMap[i] = ""
	}

	for _, result := range listOfResults {
		sectionId, _ := strconv.Atoi(strings.Split(result.Control, ".")[0])
		if sectionLeaderMap[sectionId] == "" {
			resultId := strings.ReplaceAll(result.Control+result.Title, " ", "")
			sectionLeaderMap[sectionId] = resultId
		}
	}
	// Render the progress bars for each section, apart from overall section
	for idx, section := range sections[1:] {
		section.Score = scoreMap[idx+1].Pass
		section.MaxScore = scoreMap[idx+1].Pass + scoreMap[idx+1].Fail

		if section.MaxScore > 0 {
			progressPercentage := float64(section.Score) / float64(section.MaxScore) * 100
			tmpl.ExecuteTemplate(sectionProgressBars, "progressBarTemplate", map[string]interface{}{
				"SectionName": section.Name,
				"Score":       section.Score,
				"MaxScore":    section.MaxScore,
				"Percentage":  progressPercentage,
				"Color":       section.Color,
				"AnchorID":    sectionLeaderMap[idx+1],
			})
		}
	}

	// Render Overall Progress bar
	overallPercentage := float64(overallSection.Score) / float64(overallSection.MaxScore) * 100
	tmpl.ExecuteTemplate(overallProgressBar, "overallBarTemplate", map[string]interface{}{
		"SectionName": sections[0].Name,
		"Score":       sections[0].Score,
		"MaxScore":    sections[0].MaxScore,
		"Percentage":  overallPercentage,
		"Color":       sections[0].Color,
	})

	// Execute dataTables template
	tmpl.ExecuteTemplate(dataTables, "dataTables", map[string]interface{}{
		"Tables": nil,
	})

	// Render the table of contents and detailed tables for results
	for _, result := range listOfResults {
		id := strings.ReplaceAll(result.Control+result.Title, " ", "")
		tmpl.ExecuteTemplate(tos, "tos", map[string]interface{}{
			"Id":          id,
			"Description": result.Control + " " + result.Title,
		})

		failReason := bytes.NewBuffer(nil)
		if result.Status == "Fail" {
			tmpl.ExecuteTemplate(failReason, "failReason", map[string]interface{}{
				"Reason": utils.GetFailReasonInString(result.FailReason),
			})
		}
		tmpl.ExecuteTemplate(tableTemplate, "tableTemplate", map[string]interface{}{
			"Id":           template.HTML(id),
			"ControlTitle": template.HTML(result.Control + " " + result.Title),
			"Result":       result.Status != "Fail",
			"Description":  template.HTML(strings.ReplaceAll(result.Description, "\n", "<br/>")),
			"FailReason":   template.HTML(failReason.String()),
			"Rationale":    template.HTML(strings.ReplaceAll(result.Rationale, "\n", "<br/>")),
			"Procedure":    template.HTML(strings.ReplaceAll(result.Procedure, "\n", "<br/>")),
			"References":   template.HTML(strings.ReplaceAll(result.References, "\n", "<br/>")),
		})

	}

	// Final assembly of the entire HTML body
	tmpl.ExecuteTemplate(body, "body", map[string]interface{}{
		"PopulateTable": template.HTML(tableTemplate.String()),
		"Queries":       template.HTML(dataTables.String()),
		// "TOS":                 template.HTML(tos.String()),
		"SectionProgressBars": template.HTML(sectionProgressBars.String()),
		"OverallProgressBar":  template.HTML(overallProgressBar.String()),
		"PostgresVersion":     template.HTML(fmt.Sprintf("Postgres Version: %s", database)),
	})

	return body.String()
}

func RenderHTMLTemplateForHBA(listOfResults []*model.HBAScannerResult) string {
	hbaFailRowsBodyTemplate := bytes.NewBuffer(nil)
	hbatabletemplate := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)
	tos := bytes.NewBuffer(nil)

	for _, result := range listOfResults {
		description := fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description)
		id := strings.Replace(description, " ", "", -1)
		tmpl.ExecuteTemplate(tos, "tos", map[string]interface{}{
			"Id":          id,
			"Description": description,
		})

		if result.Status == "Fail" {
			hbaFailRowsTemplate := bytes.NewBuffer(nil)
			for i, row := range result.FailRows {
				tmpl.ExecuteTemplate(hbaFailRowsTemplate, "hbaFailRowsTemplate", map[string]interface{}{
					"LineNumber": result.FailRowsLineNums[i],
					"HbaEntry":   row,
				})
			}

			headline := fmt.Sprintf("HBA Check %d - %s (Failure Report)", result.Control, result.Description)
			tmpl.ExecuteTemplate(hbaFailRowsBodyTemplate, "hbaFailRowsBodyTemplate", map[string]interface{}{
				"Headline":            headline,
				"HbaFailRowsTemplate": template.HTML(hbaFailRowsTemplate.String()),
			})

			hbafailRows := bytes.NewBuffer(nil)
			tmpl.ExecuteTemplate(hbafailRows, "hbafailRows", map[string]interface{}{
				"FailRowsInString": result.FailRowsInString,
			})

			tmpl.ExecuteTemplate(hbatabletemplate, "hbatabletemplate", map[string]interface{}{
				"Id":                 id,
				"ControlDescription": fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description),
				"Result":             false,
				"Description":        result.Description,
				"HbafailRows":        template.HTML(hbafailRows.String()),
				"Procedure":          result.Procedure,
			})

		} else {
			tmpl.ExecuteTemplate(hbatabletemplate, "hbatabletemplate", map[string]interface{}{
				"Id":                 id,
				"ControlDescription": fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description),
				"Result":             true,
				"Description":        result.Description,
				"HbafailRows":        "",
				"Procedure":          result.Procedure,
			})
		}
	}

	tmpl.ExecuteTemplate(body, "body", map[string]interface{}{
		// "TOS":                         template.HTML(tos.String()),
		"PopulateTable":               template.HTML(hbatabletemplate.String()),
		"HbaFailRowsBodyTemplatedata": template.HTML(hbaFailRowsBodyTemplate.String()),
	})

	return body.String()
}
