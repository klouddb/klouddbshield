package main

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/klouddb/klouddbshield/postgres/userlist"
	"github.com/klouddb/klouddbshield/simpletextreport"
)

type postgresRunner struct {
	postgresConfig   *postgresdb.Postgres
	builder          *strings.Builder
	postgresCheckSet utils.Set[string]
	htmlReportHelper *htmlreport.HtmlReportHelper
}

func newPostgresRunnerFromConfig(postgresConfig *postgresdb.Postgres, builder *strings.Builder,
	postgresCheckSet utils.Set[string], htmlReportHelper *htmlreport.HtmlReportHelper) *postgresRunner {
	return &postgresRunner{
		postgresConfig:   postgresConfig,
		builder:          builder,
		postgresCheckSet: postgresCheckSet,
		htmlReportHelper: htmlReportHelper,
	}
}

func (p *postgresRunner) cronProcess(ctx context.Context) error {

	_, err := p.run(ctx)
	return err
}

func (p *postgresRunner) run(ctx context.Context) (map[int]*model.Status, error) {

	postgresStore, _, err := postgresdb.Open(*p.postgresConfig)
	if err != nil {
		return nil, err
	}

	defer postgresStore.Close()

	// Determine Postgres version
	var postgresVersion string
	err = postgresStore.QueryRow("SELECT version();").Scan(&postgresVersion)
	if err != nil {
		return nil, err
	}
	// Regular expression to find the version number.
	re := regexp.MustCompile(`\d+`)
	version := re.FindString(postgresVersion)

	listOfResults, scoreMap, err := postgres.PerformAllChecks(postgresStore, ctx, version, p.postgresCheckSet)
	if err != nil {
		return nil, err
	}

	p.builder.WriteString(simpletextreport.PrintReportInFile(listOfResults, version, "Postgres Report"))

	p.htmlReportHelper.RegisterPostgresReportData(listOfResults, scoreMap,
		version, p.postgresCheckSet.Len() == 0 /* when there is any data from custom template then we need to skip summary part in htmlreport */)

	out := userlist.Run(ctx, postgresStore)
	p.htmlReportHelper.RegisterUserlistData(out)

	p.builder.WriteString("\nUsers Report")

	for _, data := range out {
		p.builder.WriteString("> " + data.Title + "\n")
		p.builder.WriteString(data.Data.Text() + "\n")
	}

	return scoreMap, nil

}

type postgresByControlRunner struct {
	postgresConfig *postgresdb.Postgres
	control        string
}

func newPostgresByControlRunnerFromConfig(cnf *config.Config) *postgresByControlRunner {
	return &postgresByControlRunner{
		postgresConfig: cnf.Postgres,
		control:        cnf.App.Control,
	}
}

func (p *postgresByControlRunner) cronProcess(ctx context.Context) error {
	return p.run(ctx)
}

func (p *postgresByControlRunner) run(ctx context.Context) error {
	postgresStore, _, err := postgresdb.Open(*p.postgresConfig)
	if err != nil {
		return err
	}
	defer postgresStore.Close()

	result := postgres.CheckByControl(postgresStore, ctx, p.control)
	if result == nil {
		return nil
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if result.Status == "Pass" {
		t.AppendSeparator()
		color := text.FgGreen
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})

	} else {
		t.AppendSeparator()
		color := text.FgHiRed
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})
		t.AppendSeparator()
		t.AppendRow(table.Row{"Fail Reason", result.FailReason})

	}
	t.AppendSeparator()
	t.AppendRow(table.Row{"Rationale", result.Rationale})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Title", result.Title})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Procedure", result.Procedure})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Control", result.Control})
	t.AppendSeparator()
	t.AppendRow(table.Row{"References", result.References})
	t.SetStyle(table.StyleLight)
	t.Render()

	return nil
}
