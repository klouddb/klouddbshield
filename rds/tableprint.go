package rds

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/klouddb/klouddbshield/model"
)

type rdsPrinter struct {
	table.Writer
	failuresLines []string
	listOfResults []*model.Result
	Sb            strings.Builder
}

func NewRDSPrinter(listOfResults []*model.Result) *rdsPrinter {
	sb := strings.Builder{}
	tablePrinter := &rdsPrinter{}
	tablePrinter.Sb = sb

	tablePrinter.Writer = table.NewWriter()
	tablePrinter.SetOutputMirror(&tablePrinter.Sb)
	tablePrinter.SetStyle(table.StyleLight)
	tablePrinter.listOfResults = listOfResults
	return tablePrinter
}

func (t *rdsPrinter) Print() string {
	t.AppendRow(table.Row{"Ctrl", "Title", "Status"})
	t.AppendSeparator()
	for _, row := range t.listOfResults {
		t.AppendRow(table.Row{row.Control, row.Title, row.Status})
		t.AppendSeparator()

		if row.Status != "Pass" {
			var ok bool
			//nolint
			var failReason string
			failReasonHeader := "\n\nFailure Report\n\n" + row.Control + "        " + row.Title
			switch ty := row.FailReason.(type) {
			case string:
				failReason, ok = row.FailReason.(string)
				if !ok {
					failReason = ""
				}
			case []map[string]interface{}:
				failReason = ""
				for _, n := range ty {
					for key, value := range n {
						failReason += fmt.Sprintf("%s:%v, ", key, value)
					}
					failReason += "\n"
				}
			default:
				failReason = ""
				// var r = reflect.TypeOf(sp)
				// failReason = fmt.Sprintf("Other:%v\n", r)
			}
			t.failuresLines = append(t.failuresLines, failReasonHeader+failReason)

		}
	}
	t.AppendSeparator()
	tableOutput := "\n\n" + t.Writer.Render() + "\n"
	for _, fl := range t.failuresLines {
		tableOutput += fl + "\n"
	}
	return tableOutput
}

func (t *rdsPrinter) SectionPrint() string {
	t.AppendRow(table.Row{"Ctrl", "Title", "Status"})
	t.AppendSeparator()
	for _, row := range t.listOfResults {
		t.AppendRow(table.Row{row.Control, row.Title, row.Status})
		t.AppendSeparator()
	}
	t.AppendSeparator()
	tableOutput := "\n\n" + t.Writer.Render() + "\n"
	return tableOutput
}

type rdsInstancePrinter struct {
	table.Writer
	lines []table.Row
	Sb    strings.Builder
}

func NewRDSInstancePrinter() *rdsInstancePrinter {
	sb := strings.Builder{}
	tablePrinter := &rdsInstancePrinter{}
	tablePrinter.Sb = sb

	tablePrinter.Writer = table.NewWriter()
	tablePrinter.SetOutputMirror(&tablePrinter.Sb)
	tablePrinter.SetStyle(table.StyleLight)
	tablePrinter.lines = append(tablePrinter.lines, table.Row{"Instance", "Status", "Current Value"})
	return tablePrinter
}

func (t *rdsInstancePrinter) AddInstance(instance, status, value string) {
	t.lines = append(t.lines, table.Row{instance, status, value})
	t.AppendSeparator()
}

func (t *rdsInstancePrinter) Print() string {
	for _, row := range t.lines {
		t.AppendRow(row)
		t.AppendSeparator()
	}
	// t.AppendFooter(table.Row{"", "", ""})
	t.AppendSeparator()
	return "\n\n" + t.Writer.Render() + "\n"
	// return t.Sb.String()
}

type sectionPrinter struct {
	table.Writer
	result *model.Result
	Sb     strings.Builder
}

func NewSectionPrinter(result *model.Result) *sectionPrinter {

	sp := &sectionPrinter{}
	sp.Sb = strings.Builder{}

	sp.Writer = table.NewWriter()
	sp.SetOutputMirror(&sp.Sb)
	sp.SetStyle(table.StyleLight)
	sp.result = result
	return sp
}

func (sp *sectionPrinter) Print() string {

	// status := fmt.Sprintf("Overall Status for %s is %s. Please check detailed status by instance below", sp.result.Control, sp.result.Status)
	// description := fmt.Sprintf("Description - %s", sp.result.Title)

	// var failReason string
	// var ok bool
	// switch ty := sp.result.FailReason.(type) {
	// case string:
	// 	failReason, ok = sp.result.FailReason.(string)
	// 	if !ok {
	// 		failReason = ""
	// 	}
	// case []map[string]interface{}:
	// 	failReason = ""
	// 	for _, n := range ty {
	// 		for key, value := range n {
	// 			failReason += fmt.Sprintf("%s:%v, ", key, value)
	// 		}
	// 		failReason += "\n"

	// 	}
	// default:
	// 	failReason = ""
	// 	// var r = reflect.TypeOf(sp)
	// 	// failReason = fmt.Sprintf("Other:%v\n", r)
	// }
	// return status + "\n" + description + failReason

	sp.AppendSeparator()
	sp.AppendRow(table.Row{"Title", sp.result.Title})

	sp.AppendSeparator()
	sp.AppendRow(table.Row{"Control", sp.result.Control})

	if sp.result.Status == "Pass" {
		sp.AppendSeparator()
		sp.AppendRow(table.Row{"Status", sp.result.Status})
	} else {
		sp.AppendSeparator()
		sp.AppendRow(table.Row{"Status", sp.result.Status})
		sp.AppendSeparator()
		// switch ty := sp.result.FailReason.(type) {

		// case string:
		// 	sp.AppendRow(table.Row{"Fail Reason", sp.result.FailReason})
		// case []map[string]interface{}:
		// 	failReason := ""
		// 	for _, n := range ty {
		// 		for key, value := range n {
		// 			failReason += fmt.Sprintf("%s:%v, ", key, value)
		// 		}
		// 		failReason += "\n"

		// 	}
		// 	sp.AppendRow(table.Row{"Fail Reason", failReason})
		// default:
		// 	var r = reflect.TypeOf(sp)
		// 	fmt.Printf("Other:%v\n", r)
		// }

	}
	sp.SetStyle(table.StyleLight)
	return sp.Render()
}
