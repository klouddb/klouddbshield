package logparser

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/hbarules"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type UnusedHBALineHelper struct {
	*parselog.HbaUnusedLineParser
	store *sql.DB
}

func NewUnusedHBALineHelper(store *sql.DB) *UnusedHBALineHelper {
	return &UnusedHBALineHelper{store: store}
}

func (i *UnusedHBALineHelper) Init(ctx context.Context, logParserCnf *config.LogParser) error {
	// check if postgres setting contains required variable or connection logs
	// for unused hba parsing we need to have any 2 of the following
	// 1. log_line_prefix contains %h or %r
	// 2. log_connections is enabled
	// 3. log_line_prefix contains %u and %d

	if logParserCnf.PgSettings.LogConnections {
		if !(strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%h") || strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%r")) &&
			!(strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%u") && strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%d")) {
			return fmt.Errorf("with log_connections enabled, please set log_line_prefix to '%%h' or '%%r' or '%%u' and '%%d'")
		}
	} else {
		if !(strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%h") || strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%r")) ||
			!(strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%u") && strings.Contains(logParserCnf.PgSettings.LogLinePrefix, "%d")) {
			return fmt.Errorf("please set log_line_prefix to '%%h' or '%%r' or '%%u' and '%%d'")
		}
	}

	var hbaRules []model.HBAFIleRules

	// if user is passing hba conf file manually then he or she are expecting that file to be scanned
	if logParserCnf.HbaConfFile != "" {
		var err error
		hbaRules, err = hbarules.ScanHBAFile(ctx, i.store, logParserCnf.HbaConfFile)
		if err != nil {
			return fmt.Errorf("Got error while scanning hba file: %v", err)
		}
	} else if i.store != nil {
		var err error
		hbaRules, err = utils.GetDatabaseAndHostForUSerFromHbaFileRules(ctx, i.store)
		if err != nil {
			return fmt.Errorf("Got error while getting hba rules: %v", err)
		}
	} else {
		return fmt.Errorf("Please provide hba file or database connection")
	}

	hbaValidator, err := hbarules.ParseHBAFileRules(hbaRules)
	if err != nil {
		return fmt.Errorf("Got error while parsing hba rules: %v", err)
	}

	i.HbaUnusedLineParser = parselog.NewHbaUnusedLines(logParserCnf, hbaValidator)
	return nil
}

func (i *UnusedHBALineHelper) GetResult(ctx context.Context) []hbarules.HBARawLine {
	return i.GetUnusedLines()
}
