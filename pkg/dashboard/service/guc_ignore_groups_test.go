package service

import (
	"context"
	"testing"

	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func TestGucDriftIgnoreHostAndGuc(t *testing.T) {
	tests := []struct {
		name           string
		ignoreScope    string
		ignoreGuc      string
		wantDrifting   int
		wantMatched    int
		wantIgnoredSrv int
		wantActiveRows int
		wantIgnRows    int
	}{
		{
			name:           "ignore single guc hides active drift",
			ignoreScope:    "guc",
			ignoreGuc:      "work_mem",
			wantDrifting:   0,
			wantMatched:    2, // reference host + ignored-drift host
			wantActiveRows: 0,
			wantIgnRows:    1,
		},
		{
			name:           "ignore host marks ignored",
			ignoreScope:    "host",
			wantDrifting:   0,
			wantMatched:    1, // reference host still matched
			wantIgnoredSrv: 1,
			wantActiveRows: 0,
			wantIgnRows:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestGucDB(t)
			ctx := context.Background()
			if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:a:5432", "host-a", "n1", map[string]string{
				"ssl": "on", "work_mem": "4MB",
			}); err != nil {
				t.Fatal(err)
			}
			if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:b:5432", "host-b", "n2", map[string]string{
				"ssl": "on", "work_mem": "32MB",
			}); err != nil {
				t.Fatal(err)
			}
			if err := reportstore.UpsertGucBaseline(ctx, db, "host-a", reportstore.HostBaselineSettings("postgres:a:5432")); err != nil {
				t.Fatal(err)
			}
			svc := NewSQLiteService(db)
			if err := svc.SetGucIgnore(ctx, tt.ignoreScope, "postgres:b:5432", tt.ignoreGuc, true); err != nil {
				t.Fatal(err)
			}
			resp, err := svc.GucDrift(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Stats.DriftingServers != tt.wantDrifting {
				t.Fatalf("drifting=%d want %d", resp.Stats.DriftingServers, tt.wantDrifting)
			}
			if resp.Stats.MatchedServers != tt.wantMatched {
				t.Fatalf("matched=%d want %d", resp.Stats.MatchedServers, tt.wantMatched)
			}
			if resp.Stats.IgnoredServers != tt.wantIgnoredSrv {
				t.Fatalf("ignored_servers=%d want %d", resp.Stats.IgnoredServers, tt.wantIgnoredSrv)
			}
			active, ignored := 0, 0
			for _, row := range resp.Rows {
				if row.TargetID != "postgres:b:5432" {
					continue
				}
				if row.Ignored {
					ignored++
				} else {
					active++
				}
			}
			if active != tt.wantActiveRows {
				t.Fatalf("active_rows=%d want %d", active, tt.wantActiveRows)
			}
			if ignored != tt.wantIgnRows {
				t.Fatalf("ignored_rows=%d want %d", ignored, tt.wantIgnRows)
			}
		})
	}
}

func TestGucServerGroupMembersVisibleWithoutBaseline(t *testing.T) {
	db := openTestGucDB(t)
	ctx := context.Background()
	svc := NewSQLiteService(db)

	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:a:5432", "host-a", "n1", map[string]string{
		"ssl": "on",
	}); err != nil {
		t.Fatal(err)
	}
	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:b:5432", "host-b", "n2", map[string]string{
		"ssl": "off",
	}); err != nil {
		t.Fatal(err)
	}

	g, err := svc.UpsertGucServerGroup(ctx, "", "testservers", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetGucServerGroupMembers(ctx, g.ID, []string{"postgres:b:5432"}); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.GucDriftQuery(ctx, g.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Stats.HostsCompared != 1 {
		t.Fatalf("hosts_compared=%d want 1 (members visible without baseline)", resp.Stats.HostsCompared)
	}
	if len(resp.HostSummaries) != 1 || resp.HostSummaries[0].TargetID != "postgres:b:5432" {
		t.Fatalf("summaries=%+v", resp.HostSummaries)
	}
	if resp.HostSummaries[0].Status != "no_baseline" {
		t.Fatalf("status=%q want no_baseline", resp.HostSummaries[0].Status)
	}
}

func TestGucServerGroupBaselineScopedDrift(t *testing.T) {
	db := openTestGucDB(t)
	ctx := context.Background()
	svc := NewSQLiteService(db)

	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:a:5432", "host-a", "n1", map[string]string{
		"ssl": "on", "work_mem": "4MB",
	}); err != nil {
		t.Fatal(err)
	}
	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:b:5432", "host-b", "n2", map[string]string{
		"ssl": "on", "work_mem": "32MB",
	}); err != nil {
		t.Fatal(err)
	}
	if err := reportstore.UpsertServerGucSnapshot(ctx, db, "postgres:c:5432", "host-c", "n3", map[string]string{
		"ssl": "off", "work_mem": "4MB",
	}); err != nil {
		t.Fatal(err)
	}

	g, err := svc.UpsertGucServerGroup(ctx, "", "prod", "prod group")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetGucServerGroupMembers(ctx, g.ID, []string{"postgres:a:5432", "postgres:b:5432"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.PutGucGroupBaselineFromHost(ctx, g.ID, "postgres:a:5432"); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.GucDriftQuery(ctx, g.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Stats.HostsCompared != 2 {
		t.Fatalf("hosts_compared=%d want 2", resp.Stats.HostsCompared)
	}
	if resp.Stats.DriftingServers != 1 {
		t.Fatalf("drifting=%d want 1", resp.Stats.DriftingServers)
	}
	for _, h := range resp.HostSummaries {
		if h.TargetID == "postgres:c:5432" {
			t.Fatal("host-c should be excluded from group drift")
		}
	}
}
