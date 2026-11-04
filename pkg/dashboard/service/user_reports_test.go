package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func TestUserReportsGroupsByInstance(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	dbs := []string{"hej", "hej1", "hej3"}
	for _, name := range dbs {
		r := inactiveUsersLogParserReport()
		r["Log Parser Summary"] = []interface{}{
			map[string]interface{}{
				"Command": "inactive_users",
				"Result":  "2 inactive users found in database\n",
				"Value": []interface{}{
					[]interface{}{"postgres"},
					[]interface{}{"romin"},
					[]interface{}{"postgres", "romin"},
				},
			},
		}
		PersistTestScanResult(t, db, r, reportstore.RunMeta{
			Trigger:    "test",
			RunnerName: "inactive_users",
			Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: name},
			StartedAt:  now,
			FinishedAt: now,
			RunStatus:  "success",
		}, "test-node", "localhost")
	}

	svc := NewSQLiteService(db)
	inactive, err := svc.InactiveUsersReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inactive.HostCount != 1 {
		t.Fatalf("hostCount=%d want 1", inactive.HostCount)
	}
	if inactive.UserCount != 2 {
		t.Fatalf("userCount=%d want 2", inactive.UserCount)
	}
	if len(inactive.Rows) != 2 {
		t.Fatalf("rows=%d want 2 (grouped by instance)", len(inactive.Rows))
	}
	for _, row := range inactive.Rows {
		if row.Instance != "localhost:5432" {
			t.Fatalf("instance=%q", row.Instance)
		}
		if row.DatabasesLabel != "3 (hej, hej1, hej3)" {
			t.Fatalf("databases_label=%q", row.DatabasesLabel)
		}
	}
}

func TestUserReportsFleet(t *testing.T) {
	tests := []struct {
		name              string
		report            map[string]interface{}
		wantInactiveHosts int
		wantInactiveUsers int
		wantCommonHosts   int
		wantCommonUsers   int
		wantInactiveMsg   bool
		wantCommonMsg     bool
	}{
		{
			name:            "no data",
			report:          map[string]interface{}{},
			wantInactiveMsg: true,
			wantCommonMsg:   true,
		},
		{
			name:              "inactive users from log parser",
			report:            inactiveUsersLogParserReport(),
			wantInactiveHosts: 1,
			wantInactiveUsers: 2,
			wantCommonHosts:   1,
			wantCommonUsers:   2,
		},
		{
			name:            "common users from users report",
			report:          samplePostgresUsersReport(),
			wantCommonHosts: 1,
			wantCommonUsers: 2,
			wantCommonMsg:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := OpenTestSQLiteDB(t)
			defer db.Close()

			now := time.Now().UTC()
			PersistTestScanResult(t, db, tc.report, reportstore.RunMeta{
				Trigger:    "test",
				RunnerName: "postgres_cis",
				Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"},
				StartedAt:  now,
				FinishedAt: now,
				RunStatus:  "success",
			}, "test-node", "localhost")

			svc := NewSQLiteService(db)
			inactive, err := svc.InactiveUsersReport(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if inactive.HostCount != tc.wantInactiveHosts {
				t.Fatalf("inactive hostCount %d want %d rows=%v", inactive.HostCount, tc.wantInactiveHosts, inactive.Rows)
			}
			if inactive.UserCount != tc.wantInactiveUsers {
				t.Fatalf("inactive userCount %d want %d", inactive.UserCount, tc.wantInactiveUsers)
			}
			if tc.wantInactiveMsg && inactive.Message == "" {
				t.Fatal("inactive message want non-empty")
			}

			common, err := svc.CommonUsersReport(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if common.HostCount != tc.wantCommonHosts {
				t.Fatalf("common hostCount %d want %d rows=%v", common.HostCount, tc.wantCommonHosts, common.Rows)
			}
			if common.UserCount != tc.wantCommonUsers {
				t.Fatalf("common userCount %d want %d", common.UserCount, tc.wantCommonUsers)
			}
			if tc.wantCommonMsg && common.Message == "" {
				t.Fatal("common message want non-empty")
			}
		})
	}
}

func TestInactiveUsersReportSeparateCronPush(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()

	now := time.Now().UTC()
	target := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"}

	// Newer CIS-only push (no log parser) — mimics */2 cron overwriting log-parser tick.
	PersistTestScanResult(t, db, samplePostgresUsersReport(), reportstore.RunMeta{
		Trigger:    "cron",
		RunnerName: "postgres_cis",
		Postgres:   target,
		StartedAt:  now,
		FinishedAt: now,
		RunStatus:  "success",
	}, "test-node", "localhost")

	older := now.Add(-5 * time.Minute)
	PersistTestScanResult(t, db, inactiveUsersLogParserReport(), reportstore.RunMeta{
		Trigger:    "cron",
		RunnerName: "inactive_users",
		Postgres:   target,
		StartedAt:  older,
		FinishedAt: older,
		RunStatus:  "success",
	}, "test-node", "localhost")

	svc := NewSQLiteService(db)
	inactive, err := svc.InactiveUsersReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inactive.UserCount != 2 {
		t.Fatalf("inactive userCount %d want 2 rows=%v", inactive.UserCount, inactive.Rows)
	}
}

func inactiveUsersLogParserReport() map[string]interface{} {
	report := samplePostgresUsersReport()
	report["Log Parser Summary"] = []interface{}{
		map[string]interface{}{
			"Command": "inactive_users",
			"Result":  "2 inactive users found in database\n",
			"Value": []interface{}{
				[]interface{}{"postgres"},
				[]interface{}{"romin"},
				[]interface{}{"stale_a", "stale_b"},
			},
		},
	}
	report["Log Parser Scan Meta"] = map[string]interface{}{
		"begin":         "2026-08-01T00:00:00Z",
		"end":           "2026-08-25T12:00:00Z",
		"files_found":   float64(2),
		"files_scanned": float64(2),
	}
	return report
}

func TestInactiveUsersReportIncludesLogFilterTimeRange(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	PersistTestScanResult(t, db, inactiveUsersLogParserReport(), reportstore.RunMeta{
		Trigger:    "test",
		RunnerName: "inactive_users",
		Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"},
		StartedAt:  now,
		FinishedAt: now,
		RunStatus:  "success",
	}, "test-node", "localhost")

	svc := NewSQLiteService(db)
	inactive, err := svc.InactiveUsersReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inactive.Rows) == 0 {
		t.Fatal("expected inactive user rows")
	}
	for _, row := range inactive.Rows {
		if row.DataSource == "aggregation" {
			if row.InactiveSince == "" {
				t.Fatalf("aggregation row missing inactive_since: %#v", row)
			}
			if !strings.HasPrefix(row.TimeRangeLabel, "inactive since ") {
				t.Fatalf("time_range_label=%q", row.TimeRangeLabel)
			}
			continue
		}
		if row.Begin != "2026-08-01T00:00:00Z" || row.End != "2026-08-25T12:00:00Z" {
			t.Fatalf("begin/end=%q/%q", row.Begin, row.End)
		}
		if row.TimeRangeLabel != "2026-08-01T00:00:00Z → 2026-08-25T12:00:00Z" {
			t.Fatalf("time_range_label=%q", row.TimeRangeLabel)
		}
	}
}

func uniqueIPLogParserReport() map[string]interface{} {
	report := samplePostgresUsersReport()
	report["Log Parser Summary"] = []interface{}{
		map[string]interface{}{
			"Command": "unique_ip",
			"Result":  "3 unique ips found\n",
			"Value":   []interface{}{"10.0.0.1", "10.0.0.2", "192.168.1.10"},
		},
	}
	report["Log Parser Scan Meta"] = map[string]interface{}{
		"begin": "2026-08-01T00:00:00Z",
		"end":   "2026-08-25T12:00:00Z",
	}
	return report
}

func unusedLinesLogParserReport() map[string]interface{} {
	report := samplePostgresUsersReport()
	report["Log Parser Summary"] = []interface{}{
		map[string]interface{}{
			"Command": "unused_lines",
			"Result":  "2 unused lines found\n",
			"Value": []interface{}{
				map[string]interface{}{"LineNo": float64(10), "Line": "host all all 127.0.0.1/32 trust"},
				map[string]interface{}{"LineNo": float64(22), "Line": "host replication all 0.0.0.0/0 md5"},
			},
		},
	}
	report["Log Parser Scan Meta"] = map[string]interface{}{
		"begin": "2026-08-01T00:00:00Z",
		"end":   "2026-08-25T12:00:00Z",
	}
	return report
}

func TestUniqueIPReport(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	for _, name := range []string{"hej", "hej1"} {
		PersistTestScanResult(t, db, uniqueIPLogParserReport(), reportstore.RunMeta{
			Trigger:    "test",
			RunnerName: "unique_ip",
			Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: name},
			StartedAt:  now,
			FinishedAt: now,
			RunStatus:  "success",
		}, "test-node", "localhost")
	}

	svc := NewSQLiteService(db)
	resp, err := svc.UniqueIPReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.HostCount != 1 {
		t.Fatalf("hostCount=%d want 1", resp.HostCount)
	}
	if resp.IPCount != 3 {
		t.Fatalf("ipCount=%d want 3", resp.IPCount)
	}
	if len(resp.Rows) != 3 {
		t.Fatalf("rows=%d want 3", len(resp.Rows))
	}
	for _, row := range resp.Rows {
		if row.Instance != "localhost:5432" {
			t.Fatalf("instance=%q", row.Instance)
		}
		if row.DatabasesLabel != "2 (hej, hej1)" {
			t.Fatalf("databases_label=%q", row.DatabasesLabel)
		}
		if row.DataSource == "aggregation" {
			if row.FirstSeen == "" {
				t.Fatalf("aggregation row missing first_seen: %#v", row)
			}
			if !strings.HasPrefix(row.TimeRangeLabel, "first seen ") {
				t.Fatalf("time_range_label=%q", row.TimeRangeLabel)
			}
			continue
		}
		if row.TimeRangeLabel != "2026-08-01T00:00:00Z → 2026-08-25T12:00:00Z" {
			t.Fatalf("time_range_label=%q", row.TimeRangeLabel)
		}
	}
}

func TestUnusedLinesReport(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	PersistTestScanResult(t, db, unusedLinesLogParserReport(), reportstore.RunMeta{
		Trigger:    "test",
		RunnerName: "unused_lines",
		Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"},
		StartedAt:  now,
		FinishedAt: now,
		RunStatus:  "success",
	}, "test-node", "localhost")

	svc := NewSQLiteService(db)
	resp, err := svc.UnusedLinesReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.HostCount != 1 {
		t.Fatalf("hostCount=%d want 1", resp.HostCount)
	}
	if resp.LineCount != 2 {
		t.Fatalf("lineCount=%d want 2", resp.LineCount)
	}
	if len(resp.Rows) != 2 {
		t.Fatalf("rows=%d want 2", len(resp.Rows))
	}
	if resp.Rows[0].LineNo != "10" || !strings.Contains(resp.Rows[0].Line, "127.0.0.1") {
		t.Fatalf("row0=%+v", resp.Rows[0])
	}
}

func passwordLeakLogParserReport() map[string]interface{} {
	report := samplePostgresUsersReport()
	report["Log Parser Summary"] = []interface{}{
		map[string]interface{}{
			"Command": "password_leak_scanner",
			"Result":  "2 leaked passwords found\n",
			"Value": []interface{}{
				map[string]interface{}{"Password": "s3cret", "Query": "ALTER USER alice PASSWORD 's3cret'"},
				map[string]interface{}{"Password": "hunter2", "Query": "CREATE ROLE bob PASSWORD 'hunter2'"},
			},
		},
	}
	report["Log Parser Scan Meta"] = map[string]interface{}{
		"begin": "2026-08-01T00:00:00Z",
		"end":   "2026-08-25T12:00:00Z",
	}
	return report
}

func TestPasswordLeakReport(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	PersistTestScanResult(t, db, passwordLeakLogParserReport(), reportstore.RunMeta{
		Trigger:    "test",
		RunnerName: "password_leak_scanner",
		Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"},
		StartedAt:  now,
		FinishedAt: now,
		RunStatus:  "success",
	}, "test-node", "localhost")

	svc := NewSQLiteService(db)
	resp, err := svc.PasswordLeakReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.HostCount != 1 {
		t.Fatalf("hostCount=%d want 1", resp.HostCount)
	}
	if resp.LeakCount != 2 {
		t.Fatalf("leakCount=%d want 2", resp.LeakCount)
	}
	if len(resp.Rows) != 2 {
		t.Fatalf("rows=%d want 2", len(resp.Rows))
	}
	if resp.Rows[0].Password == "" || resp.Rows[0].Query == "" {
		t.Fatalf("row0=%+v", resp.Rows[0])
	}
	if resp.Rows[0].TimeRangeLabel != "2026-08-01T00:00:00Z → 2026-08-25T12:00:00Z" {
		t.Fatalf("time_range_label=%q", resp.Rows[0].TimeRangeLabel)
	}
}

func emptyPasswordLeakCronReport() map[string]interface{} {
	report := samplePostgresUsersReport()
	report["Log Parser Summary"] = []interface{}{
		map[string]interface{}{
			"Command": "password_leak_scanner",
			"Result":  "0 leaked passwords found\n",
			"Value":   []interface{}{},
		},
	}
	report["Log Parser Scan Meta"] = map[string]interface{}{
		"begin": "2026-09-23T11:22:00Z",
		"end":   "2026-09-23T11:24:00Z",
	}
	return report
}

func TestPasswordLeakReportSkipsEmptyCronWindow(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	target := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"}

	PersistTestScanResult(t, db, passwordLeakLogParserReport(), reportstore.RunMeta{
		Trigger:    "manual",
		RunnerName: "password_leak_scanner",
		Postgres:   target,
		StartedAt:  now.Add(-5 * time.Minute),
		FinishedAt: now.Add(-5 * time.Minute),
		RunStatus:  "success",
	}, "test-node", "localhost")

	PersistTestScanResult(t, db, emptyPasswordLeakCronReport(), reportstore.RunMeta{
		Trigger:    "cron",
		RunnerName: "password_leak_scanner",
		Postgres:   target,
		StartedAt:  now,
		FinishedAt: now,
		RunStatus:  "success",
	}, "test-node", "localhost")

	svc := NewSQLiteService(db)
	resp, err := svc.PasswordLeakReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.LeakCount != 2 {
		t.Fatalf("leakCount=%d want 2 (empty cron window should be skipped)", resp.LeakCount)
	}
	if resp.Rows[0].TimeRangeLabel != "2026-08-01T00:00:00Z → 2026-08-25T12:00:00Z" {
		t.Fatalf("time_range_label=%q (keep older scan range when empty cron skipped)", resp.Rows[0].TimeRangeLabel)
	}
}

func TestPasswordLeakReportSkipsManyEmptyCronWindows(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	target := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"}

	// Older scan with findings.
	PersistTestScanResult(t, db, passwordLeakLogParserReport(), reportstore.RunMeta{
		Trigger:    "cron",
		RunnerName: "password_leak_scanner",
		Postgres:   target,
		StartedAt:  now.Add(-30 * time.Minute),
		FinishedAt: now.Add(-30 * time.Minute),
		RunStatus:  "success",
	}, "test-node", "localhost")

	// Many newer empty windowed ticks + non-logparser noise (like scan_commands=all).
	for i := 0; i < 20; i++ {
		tstamp := now.Add(-time.Duration(19-i) * time.Minute)
		PersistTestScanResult(t, db, samplePostgresUsersReport(), reportstore.RunMeta{
			Trigger:    "cron",
			RunnerName: "postgres_cis",
			Postgres:   target,
			StartedAt:  tstamp,
			FinishedAt: tstamp,
			RunStatus:  "success",
		}, "test-node", "localhost")
		PersistTestScanResult(t, db, emptyPasswordLeakCronReport(), reportstore.RunMeta{
			Trigger:    "cron",
			RunnerName: "password_leak_scanner",
			Postgres:   target,
			StartedAt:  tstamp.Add(time.Second),
			FinishedAt: tstamp.Add(time.Second),
			RunStatus:  "success",
		}, "test-node", "localhost")
	}

	svc := NewSQLiteService(db)
	resp, err := svc.PasswordLeakReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.LeakCount != 2 {
		t.Fatalf("leakCount=%d want 2 after many empty cron windows", resp.LeakCount)
	}
}

func TestUniqueIPReportSeparateCronPush(t *testing.T) {
	db := OpenTestSQLiteDB(t)
	defer db.Close()
	now := time.Now().UTC()
	target := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"}

	PersistTestScanResult(t, db, samplePostgresUsersReport(), reportstore.RunMeta{
		Trigger:    "cron",
		RunnerName: "postgres_cis",
		Postgres:   target,
		StartedAt:  now,
		FinishedAt: now,
		RunStatus:  "success",
	}, "test-node", "localhost")

	older := now.Add(-5 * time.Minute)
	PersistTestScanResult(t, db, uniqueIPLogParserReport(), reportstore.RunMeta{
		Trigger:    "cron",
		RunnerName: "unique_ip",
		Postgres:   target,
		StartedAt:  older,
		FinishedAt: older,
		RunStatus:  "success",
	}, "test-node", "localhost")

	svc := NewSQLiteService(db)
	resp, err := svc.UniqueIPReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.IPCount != 3 {
		t.Fatalf("ipCount=%d want 3 rows=%v", resp.IPCount, resp.Rows)
	}
}

func TestLogFilterTimeRangeLabel(t *testing.T) {
	tests := []struct {
		begin, end, want string
	}{
		{"a", "b", "a → b"},
		{"a", "", "from a"},
		{"", "b", "until b"},
		{"", "", ""},
	}
	for _, tt := range tests {
		if got := logFilterTimeRangeLabel(tt.begin, tt.end); got != tt.want {
			t.Fatalf("begin=%q end=%q got %q want %q", tt.begin, tt.end, got, tt.want)
		}
	}
}
