package logparser

import (
	"context"
	"testing"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/runner"
)

func TestPersistLogParserSummaryKeepsStructuredInactiveUsers(t *testing.T) {
	helper := &InactiveUsersHelper{
		finalResult: [][]string{
			{"postgres", "stale_a", "stale_b"},
			{"postgres"},
			{"stale_a", "stale_b"},
		},
	}
	cnf := &config.LogParser{
		Commands: []string{cons.LogParserCMD_InactiveUser},
		LogFiles: []string{"a.log"},
	}
	resp := &runner.FastRunnerResponse{
		StartTime:    time.Now().Add(-time.Millisecond),
		TotalLines:   100,
		SuccessLines: []int64{100},
	}
	fileData := map[string]interface{}{}

	PersistLogParserSummary(context.Background(), []runner.Parser{helper}, cnf, resp, fileData)

	raw, ok := fileData["Log Parser Summary"].([]interface{})
	if !ok || len(raw) == 0 {
		t.Fatalf("expected structured Log Parser Summary, got %#v", fileData["Log Parser Summary"])
	}
	entry, ok := raw[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary map, got %#v", raw[0])
	}
	if entry["Command"] != cons.LogParserCMD_InactiveUser {
		t.Fatalf("Command=%v", entry["Command"])
	}
	val, ok := entry["Value"].([][]string)
	if !ok || len(val) < 3 {
		t.Fatalf("Value missing inactive users list: %#v", entry["Value"])
	}
	if len(val[2]) != 2 || val[2][0] != "stale_a" || val[2][1] != "stale_b" {
		t.Fatalf("inactive users Value[2]=%v", val[2])
	}
}

func TestPrintSummaryTableModeStillStoresStructuredSummary(t *testing.T) {
	helper := &InactiveUsersHelper{
		finalResult: [][]string{
			{"postgres", "idle_user"},
			{"postgres"},
			{"idle_user"},
		},
	}
	cnf := &config.LogParser{
		Commands: []string{cons.LogParserCMD_InactiveUser},
		LogFiles: []string{"a.log"},
	}
	resp := &runner.FastRunnerResponse{
		StartTime:    time.Now().Add(-time.Millisecond),
		TotalLines:   10,
		SuccessLines: []int64{10},
	}
	fileData := map[string]interface{}{}

	// table mode previously stored an ASCII string; must store structured data now
	PrintSummary(context.Background(), []runner.Parser{helper}, cnf, resp, fileData, "table")

	raw, ok := fileData["Log Parser Summary"].([]interface{})
	if !ok {
		t.Fatalf("table mode must persist structured summary, got %T", fileData["Log Parser Summary"])
	}
	entry := raw[0].(map[string]interface{})
	if entry["Command"] != cons.LogParserCMD_InactiveUser {
		t.Fatalf("Command=%v", entry["Command"])
	}
}
