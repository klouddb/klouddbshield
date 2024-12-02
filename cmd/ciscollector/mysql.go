package main

import (
	"context"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/mysqldb"
	"github.com/klouddb/klouddbshield/simpletextreport"
)

type mysqlRunner struct {
	mysqlDatabase    *config.MySQL
	fileData         map[string]interface{}
	htmlReportHelper *htmlreport.HtmlReportHelper
	outputType       string
}

func newMySqlRunner(mysqlDatabase *config.MySQL, fileData map[string]interface{},
	htmlReportHelper *htmlreport.HtmlReportHelper, outputType string) *mysqlRunner {
	return &mysqlRunner{
		mysqlDatabase:    mysqlDatabase,
		fileData:         fileData,
		htmlReportHelper: htmlReportHelper,
		outputType:       outputType,
	}
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
	if m.outputType == "json" {
		m.fileData["MySQL Report"] = map[string]interface{}{
			"mysql": result, "score": score,
		}
	} else {
		m.fileData["MySQL Report"] = simpletextreport.PrintReportInFile(result, "")
	}

	m.htmlReportHelper.RegisterMysqlReportData(result, score)

	return nil
}
