package main

import (
	"context"
	"os"
	"strings"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/postgres/hbascanner"
	"github.com/klouddb/klouddbshield/simpletextreport"
)

type hbaRunner struct {
	postgresConfig   *postgresdb.Postgres
	builder          *strings.Builder
	htmlReportHelper *htmlreport.HtmlReportHelper
}

func newHBARunnerFromConfig(postgresConfig *postgresdb.Postgres, builder *strings.Builder, htmlReportHelper *htmlreport.HtmlReportHelper) *hbaRunner {
	return &hbaRunner{
		postgresConfig:   postgresConfig,
		builder:          builder,
		htmlReportHelper: htmlReportHelper,
	}
}

func (h *hbaRunner) cronProcess(ctx context.Context) error {
	_, err := h.run(ctx)
	return err
}

func (h *hbaRunner) run(ctx context.Context) ([]*model.HBAScannerResult, error) {

	postgresStore, _, err := postgresdb.Open(*h.postgresConfig)
	if err != nil {
		return nil, err
	}
	defer postgresStore.Close()

	listOfResults := hbascanner.HBAScanner(postgresStore, ctx)

	h.htmlReportHelper.RegisterHBAReportData(listOfResults)

	for i := 0; i < len(listOfResults); i++ {
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\t", " ")
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\n", " ")
		if listOfResults[i].FailRows != nil {
			for j := 0; j < len(listOfResults[i].FailRows); j++ {
				listOfResults[i].FailRows[j] = strings.ReplaceAll(listOfResults[i].FailRows[j], "\t", " ")
			}
		}
	}

	h.builder.WriteString("\nHBA Report\n" + simpletextreport.PrintHBAReportInFile(listOfResults) + "\n")

	return listOfResults, nil
}

type hbaRunnerByControl struct {
	postgresConfig *postgresdb.Postgres
	control        string
}

func newHBARunnerByControlFromConfig(cnf *config.Config) *hbaRunnerByControl {
	return &hbaRunnerByControl{
		postgresConfig: cnf.Postgres,
		control:        cnf.App.Control,
	}
}

func (h *hbaRunnerByControl) run(ctx context.Context) {

	postgresStore, _, err := postgresdb.Open(*h.postgresConfig)
	if err != nil {
		return
	}
	defer postgresStore.Close()

	result := hbascanner.HBAScannerByControl(postgresStore, ctx, h.control)
	if result == nil {
		os.Exit(1)
	}

}
