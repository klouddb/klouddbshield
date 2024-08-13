package main

import (
	"context"
	"fmt"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

type piiDbScanner struct {
	postgresConfig   *postgresdb.Postgres
	cnf              *piiscanner.Config
	htmlReportHelper *htmlreport.HtmlReportHelper
}

func newPiiDbScanner(postgresConfig *postgresdb.Postgres, piiConfig *piiscanner.Config, htmlReportHelper *htmlreport.HtmlReportHelper) *piiDbScanner {
	return &piiDbScanner{
		postgresConfig:   postgresConfig,
		cnf:              piiConfig,
		htmlReportHelper: htmlReportHelper,
	}
}

func (p *piiDbScanner) run(ctx context.Context) error {
	pgConfig := *p.postgresConfig
	pgConfig.DBName = p.cnf.Database

	store, _, err := postgresdb.Open(pgConfig)
	if err != nil {
		return fmt.Errorf("error opening postgres connection: %v", err)
	}

	dbHelper := piiscanner.NewPostgresDBHelper(p.cnf.Schema)
	piiScanner := piiscanner.NewDatabasePiiScanner(dbHelper, store, p.cnf)

	err = piiScanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("error scanning database for pii data: %v", err)
	}

	result, err := piiScanner.GetResults()
	if err != nil {
		return fmt.Errorf("error getting pii scan results: %v", err)
	}

	piiscanner.PrintTerminalOutput(result, *p.cnf)

	p.htmlReportHelper.RegisterPIIReport(result)

	piiscanner.CreateTabularOutputfile(result, *p.cnf)

	return nil
}
