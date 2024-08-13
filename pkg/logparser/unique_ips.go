package logparser

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/parselog"
)

type UniqueIPHelper struct {
	*parselog.UniqueIPParser
}

func NewUniqueIPHelper() *UniqueIPHelper {
	return &UniqueIPHelper{}
}

func (i *UniqueIPHelper) Init(ctx context.Context, logParserCnf *config.LogParser, baseParser parselog.BaseParser) error {
	// check if postgres setting contains required variable or connection logs
	if !strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%h") && !strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%r") && !logParserCnf.PgSettings.LogConnections {
		return fmt.Errorf(`Please set log_line_prefix to '%%h' or '%%r' or enable log_connections`)
	}

	i.UniqueIPParser = parselog.NewUniqueIPParser(logParserCnf, baseParser)
	return nil
}

func (i *UniqueIPHelper) GetResult(ctx context.Context) []string {

	ips := sort.StringSlice{}
	for ip := range i.GetUniqueIPs() {
		ips = append(ips, ip)
	}

	ips.Sort()

	return ips
}
