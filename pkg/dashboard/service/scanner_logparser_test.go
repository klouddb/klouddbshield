package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/dashboard/service"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func TestLogParserScanner(t *testing.T) {
	tests := []struct {
		name          string
		report        map[string]interface{}
		wantAvail     bool
		wantCmds      int
		wantPass      int
		wantDetail    string
		wantMetaFound int
		wantMetaScan  int
		wantTerminal  string
		wantSQLDetail bool
	}{
		{
			name: "inactive_users with detail",
			report: map[string]interface{}{
				"Log Parser Summary": []interface{}{
					map[string]interface{}{
						"Command":      cons.LogParserCMD_InactiveUser,
						"Parse Status": "All lines parsed successfully",
						"Result":       "2 inactive users found in database\n",
						"Value": []interface{}{
							[]interface{}{"alice", "bob"},
							[]interface{}{"alice"},
							[]interface{}{"bob", "carol"},
						},
					},
				},
			},
			wantAvail:  true,
			wantCmds:   1,
			wantPass:   0,
			wantDetail: "Inactive users in DB",
		},
		{
			name: "all four parser commands",
			report: map[string]interface{}{
				"Log Parser Summary": []interface{}{
					map[string]interface{}{
						"Command": cons.LogParserCMD_InactiveUser, "Parse Status": "All lines parsed successfully",
						"Result": "No inactive users in database",
					},
					map[string]interface{}{
						"Command": cons.LogParserCMD_UniqueIPs, "Parse Status": "All lines parsed successfully",
						"Result": "3 unique IPs found from log file\n",
						"Value":  []interface{}{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
					},
					map[string]interface{}{
						"Command": cons.LogParserCMD_HBAUnusedLines, "Parse Status": "All lines parsed successfully",
						"Result": "2 unused lines found in hba_conf file\n",
						"Value": []interface{}{
							map[string]interface{}{"LineNo": float64(10), "Line": "host all all 127.0.0.1/32 trust"},
						},
					},
					map[string]interface{}{
						"Command": cons.LogParserCMD_PasswordLeakScanner, "Parse Status": "All lines parsed successfully",
						"Result": "No leaked passwords found.",
					},
				},
			},
			wantAvail: true,
			wantCmds:  4,
			wantPass:  2,
		},
		{
			name: "sql injection with scan meta and terminal report",
			report: map[string]interface{}{
				"Log Parser Summary": []interface{}{
					map[string]interface{}{
						"Command":      cons.LogParserCMD_SqlInjectionScan,
						"Parse Status": "All lines parsed successfully",
						"Result":       "2 SQL Injection related logs found in log file\n",
						"Value":        []interface{}{"SELECT * FROM users WHERE '1'='1'", "OR 1=1"},
					},
				},
				"Log Parser Scan Meta": map[string]interface{}{
					"begin":         "2026-08-01T00:00:00Z",
					"end":           "2026-08-25T00:00:00Z",
					"files_found":   float64(3),
					"files_scanned": float64(2),
					"files": []interface{}{
						map[string]interface{}{
							"file_name": "a.log", "scanned": true, "status": "scanned", "duration_ms": float64(10),
						},
					},
				},
				"Log Parser Terminal Report": "unique_ip ::: Successfully parsed all files\n",
			},
			wantAvail:     true,
			wantCmds:      1,
			wantMetaFound: 3,
			wantMetaScan:  2,
			wantTerminal:  "Successfully parsed",
			wantSQLDetail: true,
		},
		{
			name:      "missing log parser summary",
			report:    map[string]interface{}{"Postgres Report": map[string]interface{}{}},
			wantAvail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := service.OpenTestSQLiteDB(t)
			t.Cleanup(func() { _ = db.Close() })

			pg := &postgresdb.Postgres{Host: "lp-host", Port: "5432", DBName: "shielddb"}
			service.PersistTestScanResult(t, db, tt.report, reportstore.RunMeta{
				Trigger:    "test",
				RunnerName: "test",
				StartedAt:  time.Now().UTC(),
				FinishedAt: time.Now().UTC(),
				RunStatus:  "success",
				Postgres:   pg,
			}, "test-node", pg.Host)

			svc := service.NewSQLiteService(db)
			resp, err := svc.LogParserScanner(context.Background(), "lp-host:5432")
			if err != nil {
				t.Fatal(err)
			}
			if resp.Available != tt.wantAvail {
				t.Fatalf("available: got %v want %v", resp.Available, tt.wantAvail)
			}
			if len(resp.Commands) != tt.wantCmds {
				t.Fatalf("commands: got %d want %d", len(resp.Commands), tt.wantCmds)
			}
			if tt.wantPass > 0 && resp.Pass != tt.wantPass {
				t.Fatalf("pass: got %d want %d", resp.Pass, tt.wantPass)
			}
			if tt.wantDetail != "" {
				found := false
				for _, c := range resp.Commands {
					for _, row := range c.DetailRows {
						if row.Label == tt.wantDetail {
							found = true
							break
						}
					}
				}
				if !found {
					t.Fatalf("detail row %q not found", tt.wantDetail)
				}
			}
			if tt.wantMetaFound > 0 {
				if resp.ScanMeta == nil {
					t.Fatal("expected scanMeta")
				}
				if resp.ScanMeta.FilesFound != tt.wantMetaFound || resp.ScanMeta.FilesScanned != tt.wantMetaScan {
					t.Fatalf("scanMeta files found/scanned=%d/%d want %d/%d",
						resp.ScanMeta.FilesFound, resp.ScanMeta.FilesScanned, tt.wantMetaFound, tt.wantMetaScan)
				}
				if resp.ScanMeta.Begin == "" || resp.ScanMeta.End == "" {
					t.Fatalf("expected begin/end, got %+v", resp.ScanMeta)
				}
			}
			if tt.wantTerminal != "" && !strings.Contains(resp.TerminalReport, tt.wantTerminal) {
				t.Fatalf("terminalReport=%q", resp.TerminalReport)
			}
			if tt.wantSQLDetail {
				found := false
				for _, c := range resp.Commands {
					if c.Command == cons.LogParserCMD_SqlInjectionScan && len(c.DetailRows) == 2 {
						found = true
						if c.Status != "warn" {
							t.Fatalf("sql injection status=%q want warn", c.Status)
						}
					}
				}
				if !found {
					t.Fatal("expected sql injection detail rows")
				}
			}
		})
	}
}

func TestLogParserScannerIgnoresNewerEmptyReport(t *testing.T) {
	db := service.OpenTestSQLiteDB(t)
	t.Cleanup(func() { _ = db.Close() })

	pg := &postgresdb.Postgres{Host: "lp-host", Port: "5432", DBName: "shielddb"}
	older := time.Now().UTC().Add(-2 * time.Minute)
	newer := time.Now().UTC()

	service.PersistTestScanResult(t, db, map[string]interface{}{
		"Log Parser Summary": []interface{}{
			map[string]interface{}{
				"Command":      cons.LogParserCMD_UniqueIPs,
				"Parse Status": "All lines parsed successfully",
				"Result":       "1 unique IPs found from log file\n",
				"Value":        []interface{}{"10.0.0.9"},
			},
		},
	}, reportstore.RunMeta{
		Trigger: "cron", RunnerName: "ciscollector", Postgres: pg,
		StartedAt: older, FinishedAt: older, RunStatus: "success",
	}, "test-node", pg.Host)

	// Newer PII-only style row with empty report_json (same target).
	service.PersistTestScanResult(t, db, map[string]interface{}{}, reportstore.RunMeta{
		Trigger: "cron", RunnerName: "ciscollector", Postgres: pg,
		StartedAt: newer, FinishedAt: newer, RunStatus: "success",
	}, "test-node", pg.Host)

	resp, err := service.NewSQLiteService(db).LogParserScanner(context.Background(), "lp-host:5432")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Available || len(resp.Commands) != 1 {
		t.Fatalf("expected log parser from older run, got avail=%v cmds=%d msg=%q", resp.Available, len(resp.Commands), resp.Message)
	}
	if resp.Commands[0].Command != cons.LogParserCMD_UniqueIPs {
		t.Fatalf("command=%q", resp.Commands[0].Command)
	}
}
