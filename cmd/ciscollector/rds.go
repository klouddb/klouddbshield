package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/text"
	"github.com/klouddb/klouddbshield/rds"
	"github.com/klouddb/klouddbshield/simpletextreport"
)

type rdsRunner struct {
	outputType string
}

func newRDSRunner(outputType string) *rdsRunner {
	return &rdsRunner{
		outputType: outputType,
	}
}

func (r *rdsRunner) cronProcess(ctx context.Context) error {
	r.run(ctx)
	return nil
}

func (r *rdsRunner) run(ctx context.Context) {
	fmt.Println("running RDS ")
	rds.Validate()
	listOfResults := rds.PerformAllChecks(ctx)

	output := ""
	if r.outputType == "json" {
		output = simpletextreport.PrintJsonReport(listOfResults)
	} else {
		tableData := rds.ConvertToMainTable(listOfResults)
		output = strings.ReplaceAll(string(tableData), `\n`, "\n")
	}

	fmt.Println("for detailed information check the generated output file rdssecreport.json")
	fmt.Println(output)

	// write output data to file
	err := os.WriteFile("rdssecreport.json", []byte(output), 0600)
	if err != nil {
		fmt.Println("Error while saving result in file:", text.FgHiRed.Sprint(err))
		fmt.Println("**********listOfResults*************\n", string(output))
	}
	fmt.Println("rdssecreport.json file generated")
}
