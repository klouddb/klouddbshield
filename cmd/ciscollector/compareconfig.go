package main

import (
	"context"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/postgresconfig"
)

type compareConfigRunner struct {
	baseServer        string
	connectionStrings []string
	htmlReportHelper  *htmlreport.HtmlReportHelper
}

func newCompareConfigRunner(baseServer string, connectionStrings []string, htmlReportHelper *htmlreport.HtmlReportHelper) *compareConfigRunner {
	return &compareConfigRunner{
		baseServer:        baseServer,
		connectionStrings: connectionStrings,
		htmlReportHelper:  htmlReportHelper,
	}
}

func (c *compareConfigRunner) cronProcess(ctx context.Context) error {
	return c.run(ctx)
}

func (c *compareConfigRunner) run(_ context.Context) error {

	connectionStrings := c.connectionStrings
	if c.baseServer != "" {
		connectionStrings = append([]string{c.baseServer}, c.connectionStrings...)
	}

	result, err := postgresconfig.GetAllConfigValues(connectionStrings)
	if err != nil {
		return err
	}

	var one2oneComparison *postgresconfig.ConfigCompareOne2OneResult
	if c.baseServer != "" {
		one2oneComparison = postgresconfig.CompareAllServersWithBase(result)
	}

	configCompareResult := &postgresconfig.ConfigCompareResult{
		One2OneComparison: one2oneComparison,
	}

	c.htmlReportHelper.RegisterCompareConfig(configCompareResult)

	return nil
}
