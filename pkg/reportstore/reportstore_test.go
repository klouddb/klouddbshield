package reportstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	fileData := map[string]interface{}{
		"Postgres Report": map[string]interface{}{
			"score": map[string]interface{}{"Pass": 8, "Fail": 2},
		},
		"Users Report": []interface{}{},
	}
	id, err := Persist(context.Background(), db, fileData, RunMeta{
		Trigger:    "cron",
		RunnerName: "test",
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		RunStatus:  "success",
	})
	if err != nil {
		t.Fatal(err)
	}
	row, err := GetRunByID(context.Background(), db, id)
	if err != nil || row == nil {
		t.Fatalf("get: %v", err)
	}
	if row.TotalPass != 8 || row.TotalFail != 2 {
		t.Fatalf("summary: pass=%d fail=%d", row.TotalPass, row.TotalFail)
	}
	if _, ok := row.Report["Postgres Report"]; !ok {
		t.Fatal("missing Postgres Report in decoded blob")
	}
}

func TestSummarizeFromResultArray(t *testing.T) {
	fileData := map[string]interface{}{
		"Postgres Report": map[string]interface{}{
			"result": []interface{}{
				map[string]interface{}{"Status": "Pass"},
				map[string]interface{}{"Status": "Fail"},
				map[string]interface{}{"Status": "Pass"},
			},
			"version": "18",
		},
	}
	pass, fail, score := summarizeFromReport(fileData)
	if pass != 2 || fail != 1 {
		t.Fatalf("got pass=%d fail=%d want 2/1", pass, fail)
	}
	if score < 66 || score > 67 {
		t.Fatalf("score=%v want ~66.7", score)
	}
}

func TestPurgeRetention(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	old := time.Now().UTC().AddDate(0, 0, -100)
	_, err = Persist(context.Background(), db, map[string]interface{}{"x": 1}, RunMeta{
		Trigger: "cron", StartedAt: old, FinishedAt: old,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := PurgeRetention(context.Background(), db, 90)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected purge, got %d", n)
	}
	latest, err := GetLatestRun(context.Background(), db, "")
	if err != nil {
		t.Fatal(err)
	}
	if latest != nil {
		t.Fatal("expected no rows after purge")
	}
}

func TestResolveDBPath(t *testing.T) {
	p, err := ResolveDBPath(DefaultStorage())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(p)); err != nil {
		t.Fatal(err)
	}
}

func TestRebindSQLLeavesSQLitePlaceholders(t *testing.T) {
	prevFlag := UsePostgresPlaceholders
	UsePostgresPlaceholders = false
	t.Cleanup(func() { UsePostgresPlaceholders = prevFlag })

	q := "SELECT id FROM scan_results WHERE target_id = ?"
	if got := rebindSQL(nil, q); got != q {
		t.Fatalf("nil db rebind=%q want unchanged", got)
	}

	db, err := Open(filepath.Join(t.TempDir(), "rebind.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if got := rebindSQL(db, q); got != q {
		t.Fatalf("sqlite rebind=%q want %q", got, q)
	}
}

func TestRebindPostgresPlaceholders(t *testing.T) {
	got := rebindPostgresPlaceholders("WHERE target_id = ? AND backup_compliance_json IS NOT NULL")
	want := "WHERE target_id = $1 AND backup_compliance_json IS NOT NULL"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	got = rebindPostgresPlaceholders("VALUES (?, ?, ?)")
	if got != "VALUES ($1, $2, $3)" {
		t.Fatalf("got %q", got)
	}
}

func TestRebindSQLWhenPostgresFlag(t *testing.T) {
	prev := UsePostgresPlaceholders
	UsePostgresPlaceholders = true
	t.Cleanup(func() { UsePostgresPlaceholders = prev })

	got := rebindSQL(nil, "SELECT id FROM scan_results WHERE target_id = ? AND id = ?")
	want := "SELECT id FROM scan_results WHERE target_id = $1 AND id = $2"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
