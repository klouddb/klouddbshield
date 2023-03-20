package rds

import (
	"fmt"
	"strings"
	"text/tabwriter"
)

type tablePrinter struct {
	*tabwriter.Writer
	lines []string
	Sb    strings.Builder
}

func NewTablePrinter() *tablePrinter {
	sb := strings.Builder{}
	tablePrinter := &tablePrinter{}
	tablePrinter.Sb = sb

	tablePrinter.Writer = tabwriter.NewWriter(&sb, 1, 1, 1, ' ', 0)
	tablePrinter.lines = append(tablePrinter.lines, "\nInstance      Status      Current Value")
	return tablePrinter
}

func (t *tablePrinter) AddInstance(instance, status, value string) {
	tableLine := fmt.Sprintf("%s      %s      %s", instance, status, value)
	t.lines = append(t.lines, tableLine)

}

func (t *tablePrinter) Print() string {
	for _, line := range t.lines {
		fmt.Fprintln(&t.Sb, line)
	}
	t.Writer.Flush()
	return t.Sb.String()
}
