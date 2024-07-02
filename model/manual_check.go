package model

import (
	"bytes"
	"fmt"

	"github.com/olekukonko/tablewriter"
)

type ManualCheckData interface {
	Type() string
	Text() string
}

type ManualCheckTableDescriptionAndList struct {
	Description string       `json:"Description"`
	List        []string     `json:"List"`
	Table       *SimpleTable `json:"Table"`
}

func (m ManualCheckTableDescriptionAndList) Type() string {
	return "ManualCheckTableDescriptionAndList"
}

func (m ManualCheckTableDescriptionAndList) Text() string {

	buf := bytes.Buffer{}

	table := tablewriter.NewWriter(&buf)
	table.SetHeader(m.Table.Columns)

	for _, d := range m.Table.Rows {
		row := make([]string, 0, len(d))
		for _, str := range d {
			row = append(row, fmt.Sprint(str))
		}
		table.Append(row)
	}

	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.Render()

	return buf.String()
}

type SimpleTable struct {
	Columns []string
	Rows    [][]interface{}
}
