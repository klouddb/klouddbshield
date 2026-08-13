package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/klouddb/klouddbshield/pkg/reportstore"
	_ "modernc.org/sqlite"
)

func TestGucDriftFromSnapshots(t *testing.T) {
	tests := []struct {
		name            string
		baseline        map[string]string
		snapshots       map[string]map[string]string
		wantHosts       int
		wantMatched     int
		wantDrifting    int
		wantMissing     int
		wantDriftRows   int
		wantMissingRows int
	}{
		{
			name:     "no baseline",
			baseline: nil,
			snapshots: map[string]map[string]string{
				"postgres:host:5432:db": {"ssl": "on"},
			},
			wantHosts: 0,
		},
		{
			name:     "all matched",
			baseline: map[string]string{"ssl": "on", "shared_buffers": "128MB"},
			snapshots: map[string]map[string]string{
				"postgres:host:5432:db": {"ssl": "ON", "shared_buffers": "128mb"},
			},
			wantHosts:    1,
			wantMatched:  1,
			wantDrifting: 0,
		},
		{
			name: "valid empty values are matched not missing",
			baseline: map[string]string{
				"application_name":   "",
				"cluster_name":       "",
				"default_tablespace": "",
			},
			snapshots: map[string]map[string]string{
				"postgres:host:5432:db": {
					"application_name":   "",
					"cluster_name":       "",
					"default_tablespace": "",
				},
			},
			wantHosts:   1,
			wantMatched: 1,
			wantMissing: 0,
		},
		{
			name:     "drift and missing",
			baseline: map[string]string{"ssl": "on", "max_connections": "200"},
			snapshots: map[string]map[string]string{
				"postgres:a:5432:db": {"ssl": "off"},
				"postgres:b:5432:db": {"ssl": "on", "max_connections": "200"},
			},
			wantHosts:       2,
			wantMatched:     1,
			wantDrifting:    1,
			wantMissing:     1,
			wantDriftRows:   1,
			wantMissingRows: 1,
		},
		{
			name:     "dedupe per-db snapshots same instance",
			baseline: map[string]string{"max_connections": "100", "ssl": "on"},
			snapshots: map[string]map[string]string{
				"postgres:localhost:5432:postgres": {"max_connections": "200", "ssl": "off"},
				"postgres:localhost:5432:mydb":     {"max_connections": "200", "ssl": "off"},
				"postgres:localhost:5432:hej":      {"max_connections": "200", "ssl": "off"},
			},
			wantHosts:     1,
			wantMatched:   0,
			wantDrifting:  1,
			wantDriftRows: 2, // max_connections + ssl once each
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestGucDB(t)
			ctx := context.Background()
			if tt.baseline != nil {
				if err := reportstore.UpsertGucBaseline(ctx, db, "test", tt.baseline); err != nil {
					t.Fatal(err)
				}
			}
			for targetID, settings := range tt.snapshots {
				if err := reportstore.UpsertServerGucSnapshot(ctx, db, targetID, targetID, "node-1", settings); err != nil {
					t.Fatal(err)
				}
			}

			resp, err := NewSQLiteService(db).GucDrift(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Stats.HostsCompared != tt.wantHosts {
				t.Fatalf("hosts_compared=%d want %d", resp.Stats.HostsCompared, tt.wantHosts)
			}
			if resp.Stats.MatchedServers != tt.wantMatched {
				t.Fatalf("matched=%d want %d", resp.Stats.MatchedServers, tt.wantMatched)
			}
			if resp.Stats.DriftingServers != tt.wantDrifting {
				t.Fatalf("drifting=%d want %d", resp.Stats.DriftingServers, tt.wantDrifting)
			}
			if resp.Stats.MissingServers != tt.wantMissing {
				t.Fatalf("missing_servers=%d want %d", resp.Stats.MissingServers, tt.wantMissing)
			}
			driftRows, missingRows := 0, 0
			for _, row := range resp.Rows {
				switch row.Status {
				case "drift":
					driftRows++
				case "missing":
					missingRows++
				}
			}
			if driftRows != tt.wantDriftRows {
				t.Fatalf("drift_rows=%d want %d", driftRows, tt.wantDriftRows)
			}
			if missingRows != tt.wantMissingRows {
				t.Fatalf("missing_rows=%d want %d", missingRows, tt.wantMissingRows)
			}
		})
	}
}

func TestGucDriftFromHostBaseline(t *testing.T) {
	db := openTestGucDB(t)
	ctx := context.Background()
	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:a:5432", "host-a", "n1", map[string]string{
		"ssl": "on", "work_mem": "4MB", "max_connections": "100",
	}); err != nil {
		t.Fatal(err)
	}
	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:b:5432", "host-b", "n2", map[string]string{
		"ssl": "on", "work_mem": "32MB", "max_connections": "100",
	}); err != nil {
		t.Fatal(err)
	}
	if err := reportstore.UpsertGucBaseline(ctx, db, "host-a", reportstore.HostBaselineSettings("postgres:a:5432")); err != nil {
		t.Fatal(err)
	}

	resp, err := NewSQLiteService(db).GucDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Stats.BaselineSource != "host" {
		t.Fatalf("source=%q", resp.Stats.BaselineSource)
	}
	if resp.Stats.HostsCompared != 2 {
		t.Fatalf("hosts=%d", resp.Stats.HostsCompared)
	}
	if resp.Stats.DriftingServers != 1 {
		t.Fatalf("drifting=%d", resp.Stats.DriftingServers)
	}
	foundWorkMem := false
	for _, row := range resp.Rows {
		if row.Guc == "work_mem" && row.Live == "32MB" && row.Baseline == "4MB" {
			foundWorkMem = true
		}
	}
	if !foundWorkMem {
		t.Fatalf("expected work_mem drift row, got %+v", resp.Rows)
	}
	var baselineStatus string
	for _, h := range resp.HostSummaries {
		if h.TargetID == "postgres:a:5432" {
			baselineStatus = h.Status
		}
	}
	if baselineStatus != "baseline" {
		t.Fatalf("reference host status=%q", baselineStatus)
	}
}

func openTestGucDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := reportstore.EnsureScanResultsSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}
