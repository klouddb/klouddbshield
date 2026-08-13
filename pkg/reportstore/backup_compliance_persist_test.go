package reportstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

func TestPersistBackupComplianceReport(t *testing.T) {
	prev := RunsTable
	RunsTable = "scan_results"
	t.Cleanup(func() { RunsTable = prev })

	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := EnsureScanResultsSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	pg := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"}
	payload := map[string]interface{}{
		"host": "localhost:5432",
		"summary": map[string]interface{}{
			"total_backups": 2,
			"successful":    1,
			"failed":        1,
			"unauthorized":  2,
		},
		"backups": []interface{}{
			map[string]interface{}{
				"backup_type":       "pg_dump",
				"status":            "success",
				"compliance_status": "unauthorized",
			},
		},
	}
	meta := BackupComplianceReportMeta{NodeID: "n1", Hostname: "host1", Postgres: pg}

	if err := PersistBackupComplianceReport(context.Background(), db, meta, payload); err != nil {
		t.Fatal(err)
	}

	row, err := GetLatestRunWithBackupCompliance(context.Background(), db, TargetID(pg))
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.Report == nil {
		t.Fatal("expected backup_compliance_json")
	}
	host, _ := row.Report["host"].(string)
	if host != "localhost:5432" {
		t.Fatalf("host=%v want localhost:5432", row.Report["host"])
	}

	payload["summary"] = map[string]interface{}{
		"total_backups": 3,
		"successful":    2,
		"failed":        1,
		"unauthorized":  3,
	}
	if err := PersistBackupComplianceReport(context.Background(), db, meta, payload); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM scan_results
		WHERE target_id = ? AND backup_compliance_json IS NOT NULL
	`, TargetID(pg)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("row count=%d want 2 (each scan inserts a new row)", count)
	}

	row2, err := GetLatestRunWithBackupCompliance(context.Background(), db, TargetID(pg))
	if err != nil {
		t.Fatal(err)
	}
	if row2 == nil || row2.Report == nil {
		t.Fatal("expected latest backup_compliance_json")
	}
	sum, ok := row2.Report["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("summary type=%T want map", row2.Report["summary"])
	}
	// encoding/json decodes numbers as float64.
	got, ok := sum["total_backups"].(float64)
	if !ok || got != 3 {
		t.Fatalf("total_backups=%v (%T) want 3", sum["total_backups"], sum["total_backups"])
	}
}
