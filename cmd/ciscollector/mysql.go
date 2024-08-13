package main

import (
	"context"
	"strings"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/mysqldb"
	"github.com/klouddb/klouddbshield/simpletextreport"
)

type mysqlRunner struct {
	mysqlDatabase    *config.MySQL
	builder          *strings.Builder
	htmlReportHelper *htmlreport.HtmlReportHelper
}

func newMySqlRunner(mysqlDatabase *config.MySQL, builder *strings.Builder, htmlReportHelper *htmlreport.HtmlReportHelper) *mysqlRunner {
	return &mysqlRunner{mysqlDatabase: mysqlDatabase, builder: builder, htmlReportHelper: htmlReportHelper}
}

func (m *mysqlRunner) cronProcess(ctx context.Context) error {
	return m.run(ctx)
}

func (m *mysqlRunner) run(ctx context.Context) error {
	mysqlStore, _, err := mysqldb.Open(*m.mysqlDatabase)
	if err != nil {
		return err
	}
	defer mysqlStore.Close()

	result, score := mysql.PerformAllChecks(mysqlStore, ctx)
	m.builder.WriteString(simpletextreport.PrintReportInFile(result, "", "MySQL Report"))

	// b, _ := json.Marshal(result)
	// fmt.Println(string(b))

	m.htmlReportHelper.RegisterMysqlReportData(result, score)

	return nil
}
