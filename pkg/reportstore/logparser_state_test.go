package reportstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

func TestLogParserAggregationMergeOnPersist(t *testing.T) {
	ctx := context.Background()
	db, openErr := Open(filepath.Join(t.TempDir(), "test.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer db.Close()
	RunsTable = "scan_results"
	if err := EnsureScanResultsSchema(ctx, db); err != nil {
		t.Fatal(err)
	}

	report1 := map[string]interface{}{
		"Log Parser Summary": []interface{}{
			map[string]interface{}{
				"Command": cons.LogParserCMD_InactiveUser,
				"Value": []interface{}{
					[]interface{}{"postgres"},
					[]interface{}{"romin"},
					[]interface{}{"alice", "bob"},
				},
			},
		},
	}
	t1 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	_, err := PersistScanResult(ctx, db, report1, ScanResultMeta{
		RunMeta: RunMeta{
			Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"},
			StartedAt:  t1,
			FinishedAt: t1,
			RunStatus:  "success",
		},
		NodeID: "n1", Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}

	states, err := ListLogParserInactiveUsers(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("inactive states=%d want 2", len(states))
	}

	report2 := map[string]interface{}{
		"Log Parser Scan Meta": map[string]interface{}{
			"begin": "2026-09-29T12:36:00Z",
			"end":   "2026-09-29T12:38:00Z",
		},
		"Log Parser Summary": []interface{}{
			map[string]interface{}{
				"Command": cons.LogParserCMD_InactiveUser,
				"Value": []interface{}{
					[]interface{}{"postgres"},
					[]interface{}{"romin"},
					[]interface{}{},
				},
			},
		},
	}
	t2 := time.Date(2026, 9, 29, 12, 40, 0, 0, time.UTC)
	_, err = PersistScanResult(ctx, db, report2, ScanResultMeta{
		RunMeta: RunMeta{
			Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"},
			StartedAt:  t2,
			FinishedAt: t2,
			RunStatus:  "success",
		},
		NodeID: "n1", Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	states, err = ListLogParserInactiveUsers(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("after empty windowed scan states=%d want 2 (unchanged)", len(states))
	}

	report3 := map[string]interface{}{
		"Log Parser Summary": []interface{}{
			map[string]interface{}{
				"Command": cons.LogParserCMD_InactiveUser,
				"Value": []interface{}{
					[]interface{}{"postgres"},
					[]interface{}{"romin"},
					[]interface{}{"alice"},
				},
			},
		},
	}
	t3 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	_, err = PersistScanResult(ctx, db, report3, ScanResultMeta{
		RunMeta: RunMeta{
			Postgres:   &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "hej"},
			StartedAt:  t3,
			FinishedAt: t3,
			RunStatus:  "success",
		},
		NodeID: "n1", Hostname: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	states, err = ListLogParserInactiveUsers(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].User != "alice" {
		t.Fatalf("after full scan states=%v", states)
	}
}
