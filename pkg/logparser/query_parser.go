package logparser

import (
	"context"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
)

type QueryParseHelper struct {
	*parselog.QueryParser
}

func NewQueryParseHelper() *QueryParseHelper {
	return &QueryParseHelper{}
}

func (i *QueryParseHelper) Init(ctx context.Context, cnf *config.Config) error {

	i.QueryParser = parselog.NewQueryParser(cnf)
	return i.QueryParser.Init()
}

func (i *QueryParseHelper) GetResult(ctx context.Context) map[piiscanner.PIILabel][]parselog.PIIResp {
	return i.QueryParser.GetPII()
}

type SQLInjectionHelper struct {
	*parselog.SqlInjectionScanner
}

func NewSQLInjectionHelper() *SQLInjectionHelper {
	return &SQLInjectionHelper{}
}

func (i *SQLInjectionHelper) Init(ctx context.Context, cnf *config.LogParser) error {
	i.SqlInjectionScanner = parselog.NewSqlInjectionScanner(cnf)
	return nil
}

func (i *SQLInjectionHelper) GetResult(ctx context.Context) []string {
	return i.SqlInjectionScanner.GetQueries()
}
