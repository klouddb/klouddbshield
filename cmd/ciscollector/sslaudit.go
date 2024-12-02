package main

import (
	"context"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/klouddb/klouddbshield/postgres/sslaudit"
)

type sslAuditor struct {
	postgresConfig   *postgresdb.Postgres
	htmlReportHelper *htmlreport.HtmlReportHelper
}

func newSslAuditor(postgresConfig *postgresdb.Postgres, htmlReportHelper *htmlreport.HtmlReportHelper) *sslAuditor {
	return &sslAuditor{
		postgresConfig:   postgresConfig,
		htmlReportHelper: htmlReportHelper,
	}
}

func (h *sslAuditor) cronProcess(ctx context.Context) error {
	return h.run(ctx)
}

func (h *sslAuditor) run(ctx context.Context) error {
	postgresStore, _, err := postgresdb.Open(*h.postgresConfig)
	if err != nil {
		return err
	}
	defer postgresStore.Close()

	result, err := sslaudit.AuditSSL(ctx, postgresStore, h.postgresConfig.Host, h.postgresConfig.Port)
	if err != nil {
		return err
	}

	h.htmlReportHelper.RegisterSSLReport(result)

	postgres.PrintSSLAuditSummary(result)

	return nil
}
