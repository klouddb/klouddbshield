package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/repository/sqlite"
)

func TestBackupComplianceSummaryAndHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "main.db")
	repo, err := sqlite.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}

	prev := reportstore.RunsTable
	reportstore.RunsTable = "scan_results"
	t.Cleanup(func() { reportstore.RunsTable = prev })

	pg := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"}
	payload := map[string]interface{}{
		"host": "localhost:5432",
		"policy": map[string]interface{}{
			"allowed_start": "23:00",
			"allowed_end":   "01:00",
			"allowed_days":  []interface{}{"saturday", "sunday"},
			"timezone":      "UTC",
		},
		"summary": map[string]interface{}{
			"total_backups": 2,
			"successful":    1,
			"failed":        1,
			"unauthorized":  2,
		},
		"backups": []interface{}{
			map[string]interface{}{
				"backup_type": "pg_dump", "database": "backup_test", "user": "postgres",
				"status": "success", "start_time": "2026-07-10T06:24:15Z",
				"compliance_status": "unauthorized", "duration_seconds": 1,
			},
			map[string]interface{}{
				"backup_type": "pgbackrest", "database": "postgres", "user": "postgres",
				"status": "failed", "start_time": "2026-07-10T06:47:20Z",
				"compliance_status": "unauthorized", "duration_seconds": 0,
			},
		},
	}
	if err := repo.PersistBackupComplianceReport(context.Background(), reportstore.BackupComplianceReportMeta{
		NodeID: "n1", Hostname: "h1", Postgres: pg,
	}, payload); err != nil {
		t.Fatal(err)
	}

	svc := New(repo)
	sum, err := svc.BackupComplianceSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Available || sum.TotalBackups != 2 || sum.Unauthorized != 2 {
		t.Fatalf("summary=%+v", sum)
	}
	if len(sum.Hosts) != 1 || len(sum.Hosts[0].AllowedDays) != 2 {
		t.Fatalf("hosts allowed_days=%+v", sum.Hosts)
	}
	if sum.Hosts[0].PolicySource != policySourceCollector {
		t.Fatalf("policy_source=%s want collector_config", sum.Hosts[0].PolicySource)
	}

	hist, err := svc.BackupComplianceHistory(context.Background(), BackupComplianceHistoryFilter{
		Date: "last_30_days", BackupType: "pg_dump", Status: "unauthorized",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hist.Backups) != 1 || hist.Backups[0].BackupType != "pg_dump" {
		t.Fatalf("history=%+v", hist.Backups)
	}
	if len(hist.Unauthorized) != 1 {
		t.Fatalf("unauthorized=%d", len(hist.Unauthorized))
	}
}

func TestBackupCompliancePolicyPriority_DashboardWhenConfigEmpty(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "main.db")
	repo, err := sqlite.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	prev := reportstore.RunsTable
	reportstore.RunsTable = "scan_results"
	t.Cleanup(func() { reportstore.RunsTable = prev })

	pg := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"}
	payload := map[string]interface{}{
		"host":   "localhost:5432",
		"policy": map[string]interface{}{},
		"summary": map[string]interface{}{
			"total_backups": 1, "successful": 1, "failed": 0, "unauthorized": 0,
		},
		"backups": []interface{}{
			map[string]interface{}{
				"backup_type": "pg_dump", "database": "db", "user": "postgres",
				"status": "success", "start_time": "2026-07-10T10:00:00Z",
				"compliance_status": "authorized", "duration_seconds": 1,
			},
		},
	}
	if err := repo.PersistBackupComplianceReport(context.Background(), reportstore.BackupComplianceReportMeta{
		NodeID: "n1", Hostname: "h1", Postgres: pg,
	}, payload); err != nil {
		t.Fatal(err)
	}

	svc := New(repo)
	_, err = svc.PutBackupCompliancePolicy(context.Background(), BackupCompliancePolicyRequest{
		AllowedStart: "02:00",
		AllowedEnd:   "04:00",
		Timezone:     "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}

	sum, err := svc.BackupComplianceSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts[0].PolicySource != policySourceDashboard {
		t.Fatalf("source=%s want dashboard", sum.Hosts[0].PolicySource)
	}
	if sum.Unauthorized != 1 {
		t.Fatalf("unauthorized=%d want 1", sum.Unauthorized)
	}

	// Collector pushed dashboard window into report — must still label (dashboard), not (config).
	payload["policy"] = map[string]interface{}{
		"allowed_start": "02:00",
		"allowed_end":   "04:00",
		"timezone":      "UTC",
		"policy_source": "dashboard",
	}
	if err := repo.PersistBackupComplianceReport(context.Background(), reportstore.BackupComplianceReportMeta{
		NodeID: "n1", Hostname: "h1", Postgres: pg,
	}, payload); err != nil {
		t.Fatal(err)
	}
	sum, err = svc.BackupComplianceSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts[0].PolicySource != policySourceDashboard {
		t.Fatalf("stamped dashboard source=%s want dashboard", sum.Hosts[0].PolicySource)
	}

	payload["policy"] = map[string]interface{}{
		"allowed_start": "09:00",
		"allowed_end":   "11:00",
		"timezone":      "UTC",
		"policy_source": "collector_config",
	}
	if err := repo.PersistBackupComplianceReport(context.Background(), reportstore.BackupComplianceReportMeta{
		NodeID: "n1", Hostname: "h1", Postgres: pg,
	}, payload); err != nil {
		t.Fatal(err)
	}
	sum, err = svc.BackupComplianceSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts[0].PolicySource != policySourceCollector {
		t.Fatalf("source=%s want collector_config after config set", sum.Hosts[0].PolicySource)
	}
	if sum.Unauthorized != 0 {
		t.Fatalf("unauthorized=%d want 0", sum.Unauthorized)
	}
}

func TestResolveEffectivePolicy_AllCases(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "main.db")
	repo, err := sqlite.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := New(repo)

	_, err = svc.PutBackupCompliancePolicy(context.Background(), BackupCompliancePolicyRequest{
		AllowedStart: "02:00",
		AllowedEnd:   "04:00",
		Timezone:     "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		report     map[string]interface{}
		wantSource string
		wantStart  string
		wantEnd    string
	}{
		{
			name:       "empty report uses dashboard db",
			report:     map[string]interface{}{"policy": map[string]interface{}{}},
			wantSource: policySourceDashboard,
			wantStart:  "02:00",
			wantEnd:    "04:00",
		},
		{
			name: "dashboard stamp uses live db not stale report times",
			report: map[string]interface{}{
				"policy": map[string]interface{}{
					"allowed_start": "12:00",
					"allowed_end":   "03:00",
					"policy_source": "dashboard",
				},
			},
			wantSource: policySourceDashboard,
			wantStart:  "02:00",
			wantEnd:    "04:00",
		},
		{
			name: "collector_config stamp wins over dashboard",
			report: map[string]interface{}{
				"policy": map[string]interface{}{
					"allowed_start": "12:00",
					"allowed_end":   "03:00",
					"policy_source": "collector_config",
				},
			},
			wantSource: policySourceCollector,
			wantStart:  "12:00",
			wantEnd:    "03:00",
		},
		{
			name: "legacy report window without stamp treated as config",
			report: map[string]interface{}{
				"policy": map[string]interface{}{
					"allowed_start": "23:00",
					"allowed_end":   "01:00",
				},
			},
			wantSource: policySourceCollector,
			wantStart:  "23:00",
			wantEnd:    "01:00",
		},
		{
			name: "explicit none falls back to dashboard",
			report: map[string]interface{}{
				"policy": map[string]interface{}{
					"policy_source": "none",
				},
			},
			wantSource: policySourceDashboard,
			wantStart:  "02:00",
			wantEnd:    "04:00",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, src, err := svc.resolveEffectivePolicy(context.Background(), tc.report)
			if err != nil {
				t.Fatal(err)
			}
			if src != tc.wantSource {
				t.Fatalf("source=%s want %s", src, tc.wantSource)
			}
			if p.AllowedStart != tc.wantStart || p.AllowedEnd != tc.wantEnd {
				t.Fatalf("window=%s-%s want %s-%s", p.AllowedStart, p.AllowedEnd, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestBackupComplianceReeval_OvernightAndDays(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "main.db")
	repo, err := sqlite.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	prev := reportstore.RunsTable
	reportstore.RunsTable = "scan_results"
	t.Cleanup(func() { reportstore.RunsTable = prev })

	pg := &postgresdb.Postgres{Host: "localhost", Port: "5432", DBName: "postgres"}
	// Monday 2026-07-20 10:00 UTC = 15:30 IST — outside 02:00-04:00 UTC dashboard window.
	payload := map[string]interface{}{
		"host": "localhost:5432",
		"policy": map[string]interface{}{
			"policy_source": "none",
		},
		"summary": map[string]interface{}{"total_backups": 2, "successful": 2, "failed": 0, "unauthorized": 0},
		"backups": []interface{}{
			map[string]interface{}{
				"backup_type": "pg_dump", "database": "db", "user": "postgres",
				"status": "success", "start_time": "2026-07-20T10:00:00Z",
				"compliance_status": "authorized", "duration_seconds": 1,
			},
			map[string]interface{}{
				"backup_type": "pg_dump", "database": "db", "user": "postgres",
				"status": "auth_failed", "start_time": "2026-07-20T02:30:00Z",
				"compliance_status": "authorized", "duration_seconds": 0,
			},
		},
	}
	if err := repo.PersistBackupComplianceReport(context.Background(), reportstore.BackupComplianceReportMeta{
		NodeID: "n1", Hostname: "h1", Postgres: pg,
	}, payload); err != nil {
		t.Fatal(err)
	}
	svc := New(repo)
	_, err = svc.PutBackupCompliancePolicy(context.Background(), BackupCompliancePolicyRequest{
		AllowedStart: "02:00",
		AllowedEnd:   "04:00",
		Timezone:     "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}

	sum, err := svc.BackupComplianceSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unauthorized != 1 {
		t.Fatalf("unauthorized=%d want 1 (10:00 out, 02:30 in)", sum.Unauthorized)
	}
	if sum.Failed != 1 || sum.Success != 1 {
		t.Fatalf("success=%d failed=%d (status independent of compliance)", sum.Success, sum.Failed)
	}

	// Days-only: Monday excluded.
	_, err = svc.PutBackupCompliancePolicy(context.Background(), BackupCompliancePolicyRequest{
		AllowedStart: "00:00",
		AllowedEnd:   "23:59",
		AllowedDays:  []string{"saturday", "sunday"},
		Timezone:     "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, err = svc.BackupComplianceSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unauthorized != 2 {
		t.Fatalf("unauthorized=%d want 2 on Monday with weekend-only days", sum.Unauthorized)
	}
}

func TestPutBackupCompliancePolicy_Validation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "main.db")
	repo, err := sqlite.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := New(repo)

	if _, err := svc.PutBackupCompliancePolicy(context.Background(), BackupCompliancePolicyRequest{
		AllowedStart: "25:00",
		AllowedEnd:   "04:00",
	}); err == nil {
		t.Fatal("expected invalid start error")
	}
	got, err := svc.PutBackupCompliancePolicy(context.Background(), BackupCompliancePolicyRequest{
		AllowedStart: "02:00",
		AllowedEnd:   "04:00",
		AllowedDays:  []string{"mon", "saturday"},
		Timezone:     "Asia/Kolkata",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Configured || got.Source != policySourceDashboard || got.Timezone != "Asia/Kolkata" {
		t.Fatalf("got=%+v", got)
	}
}
