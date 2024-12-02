package htmlreport

import (
	"context"
	"database/sql"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/hbarules"
	"github.com/klouddb/klouddbshield/pkg/logparser"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/runner"
)

type LogparserHTMLReport struct {
	Error           string
	InactiveUsers   *SimplifiedInactiveUserData
	UniqueIPs       *UniqueIPRenderData
	UnusedHBALines  *UnusedHBALinesRenderData
	LeakedPasswords *PasswordLeakRenderData
	SQLInjection    *SQLInjectionRenderData
}

type PasswordLeakRenderData struct {
	LeakedPasswords []parselog.LeakedPasswordResponse
}

type SQLInjectionRenderData struct {
	Logs []string
}

type UniqueIPRenderData struct {
	IPs []string
}

type UnusedHBALinesRenderData struct {
	Lines []hbarules.HBARawLine
}

type SimplifiedInactiveUserData struct {
	UsersFromDB       string
	UsersFromLog      string
	InactiveUsersInDB string
}

func GetSimplifiedInactiveUsers(userdata [][]string) *SimplifiedInactiveUserData {
	if len(userdata) == 0 {
		return nil
	}
	out := &SimplifiedInactiveUserData{}

	if len(userdata[0]) > 0 {
		out.UsersFromDB = strings.Join(userdata[0], ", ")
	}
	out.UsersFromLog = strings.Join(userdata[1], ", ")
	if len(userdata[2]) > 0 {
		out.InactiveUsersInDB = strings.Join(userdata[2], ", ")
	}

	return out
}

func (h *HtmlReportHelper) RanderLogParserError(err error) {
	h.AddTab("Log Parser", LogparserHTMLReport{
		Error: err.Error(),
	})
}

func (h *HtmlReportHelper) RenderLogparserResponse(ctx context.Context, store *sql.DB, parsers []runner.Parser) {
	data := LogparserHTMLReport{}

	for _, r := range parsers {
		switch r := r.(type) {
		case *logparser.UnusedHBALineHelper:
			data.UnusedHBALines = &UnusedHBALinesRenderData{
				Lines: r.GetResult(ctx),
			}

		case *logparser.UniqueIPHelper:
			data.UniqueIPs = &UniqueIPRenderData{
				IPs: r.GetResult(ctx),
			}

		case *logparser.InactiveUsersHelper:
			userdata := r.GetResult(ctx)
			data.InactiveUsers = GetSimplifiedInactiveUsers(userdata)

		case *logparser.PasswordLeakHelper:
			data.LeakedPasswords = &PasswordLeakRenderData{
				LeakedPasswords: r.GetResult(ctx),
			}
		case *logparser.SQLInjectionHelper:
			data.SQLInjection = &SQLInjectionRenderData{
				Logs: r.GetResult(ctx),
			}
		}
	}

	h.AddTab("Log Parser", data)
}
