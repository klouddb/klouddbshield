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

func (i *QueryParseHelper) Init(ctx context.Context, cnf *config.Config, baseParser parselog.BaseParser) error {

	i.QueryParser = parselog.NewQueryParser(cnf, baseParser)
	return i.QueryParser.Init()
}

func (i *QueryParseHelper) GetResult(ctx context.Context) map[piiscanner.PIILabel][]parselog.PIIResp {
	return i.QueryParser.GetPII()
}
