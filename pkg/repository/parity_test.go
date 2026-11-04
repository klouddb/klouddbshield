package repository_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/repository"
	pgstore "github.com/klouddb/klouddbshield/pkg/repository/postgres"
	"github.com/klouddb/klouddbshield/pkg/repository/sqlite"
)

func TestDashboardStorageParitySQLite(t *testing.T) {
	ctx := context.Background()
	repo, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "parity.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	exerciseDashboardStorage(t, repo)
}

func TestDashboardStorageParityPostgres(t *testing.T) {
	ctx := context.Background()
	url := postgresParityURL()
	if err := ensurePostgresParityDB(ctx, url); err != nil {
		t.Skipf("postgres not available for parity test: %v", err)
	}
	repo, err := pgstore.Open(ctx, url)
	if err != nil {
		t.Skipf("postgres open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
		reportstore.UsePostgresPlaceholders = false
	})
	if err := truncatePostgresParity(ctx, url); err != nil {
		t.Fatal(err)
	}
	exerciseDashboardStorage(t, repo)
}

func postgresParityURL() string {
	if u := os.Getenv("KSHIELD_POSTGRES_TEST_URL"); u != "" {
		return u
	}
	return "postgres://postgres:postgres@127.0.0.1:5432/kshield_parity_test?sslmode=disable"
}

func ensurePostgresParityDB(ctx context.Context, url string) error {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err == nil {
		return nil
	}
	admin, err := sql.Open("postgres", "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable")
	if err != nil {
		return err
	}
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		return err
	}
	_, _ = admin.ExecContext(ctx, `CREATE DATABASE kshield_parity_test`)
	db2, err := sql.Open("postgres", url)
	if err != nil {
		return err
	}
	defer db2.Close()
	return db2.PingContext(ctx)
}

func truncatePostgresParity(ctx context.Context, url string) error {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `
		TRUNCATE TABLE
			collector_logs,
			collector_activity,
			collector_runs,
			collector_status,
			guc_server_group_members,
			guc_server_groups,
			guc_drift_ignores,
			server_guc_snapshots,
			guc_baseline,
			backup_compliance_policy,
			scan_results
		RESTART IDENTITY CASCADE
	`)
	return err
}

func exerciseDashboardStorage(t *testing.T, repo repository.Repository) {
	t.Helper()
	ctx := context.Background()
	pg := &postgresdb.Postgres{Host: "parity-host", Port: "5432", DBName: "paritydb"}
	tid := reportstore.TargetID(pg)

	id, err := repo.PersistScanResult(ctx, map[string]interface{}{
		"Postgres Report": map[string]interface{}{
			"score": map[string]interface{}{"Pass": float64(2), "Fail": float64(1)},
		},
	}, reportstore.ScanResultMeta{
		RunMeta: reportstore.RunMeta{
			Trigger:     "manual",
			RunnerName:  "parity-test",
			FeaturesRun: []string{"all"},
			Postgres:    pg,
		},
		NodeID:   "node-1",
		Hostname: "parity-host",
	})
	if err != nil {
		t.Fatalf("PersistScanResult: %v", err)
	}
	if id == "" {
		t.Fatal("PersistScanResult returned empty id")
	}

	latest, err := repo.GetLatestRun(ctx, tid)
	if err != nil {
		t.Fatalf("GetLatestRun: %v", err)
	}
	if latest == nil || latest.ID != id {
		t.Fatalf("GetLatestRun id=%v want %s", latest, id)
	}
	byID, err := repo.GetRunByID(ctx, id)
	if err != nil || byID == nil || byID.ID != id {
		t.Fatalf("GetRunByID: %+v %v", byID, err)
	}
	runs, err := repo.GetRuns(ctx, 10)
	if err != nil || len(runs) == 0 {
		t.Fatalf("GetRuns: %d %v", len(runs), err)
	}
	ids, err := repo.ListRunTargetIDs(ctx)
	if err != nil || len(ids) == 0 {
		t.Fatalf("ListRunTargetIDs: %v %v", ids, err)
	}
	forTarget, err := repo.GetRunsForTarget(ctx, tid, 5)
	if err != nil || len(forTarget) == 0 {
		t.Fatalf("GetRunsForTarget: %d %v", len(forTarget), err)
	}

	if err := repo.PersistPIIReport(ctx, pg, map[string]interface{}{"findings": float64(3)}); err != nil {
		t.Fatalf("PersistPIIReport: %v", err)
	}
	withPII, err := repo.GetLatestRunWithPII(ctx, tid)
	if err != nil || withPII == nil || withPII.PiiReport == nil {
		t.Fatalf("GetLatestRunWithPII: %+v %v", withPII, err)
	}

	if err := repo.PersistBackupComplianceReport(ctx, reportstore.BackupComplianceReportMeta{
		NodeID: "node-1", Hostname: "parity-host", Postgres: pg,
	}, map[string]interface{}{
		"host": "parity-host:5432",
		"summary": map[string]interface{}{
			"total_backups": float64(2),
		},
	}); err != nil {
		t.Fatalf("PersistBackupComplianceReport: %v", err)
	}
	bc, err := repo.GetLatestRunWithBackupCompliance(ctx, tid)
	if err != nil || bc == nil || bc.Report == nil {
		t.Fatalf("GetLatestRunWithBackupCompliance: %+v %v", bc, err)
	}
	list, err := repo.ListLatestBackupComplianceReports(ctx)
	if err != nil || len(list) == 0 {
		t.Fatalf("ListLatestBackupComplianceReports: %d %v", len(list), err)
	}

	if err := repo.UpsertBackupCompliancePolicy(ctx, reportstore.BackupCompliancePolicyStored{
		AllowedStart: "10:00",
		AllowedEnd:   "18:00",
		Timezone:     "Asia/Kolkata",
		AllowedDays:  []string{"Mon", "Tue"},
	}); err != nil {
		t.Fatalf("UpsertBackupCompliancePolicy: %v", err)
	}
	pol, _, err := repo.GetBackupCompliancePolicy(ctx)
	if err != nil || pol.AllowedStart != "10:00" || pol.Timezone != "Asia/Kolkata" {
		t.Fatalf("GetBackupCompliancePolicy: %+v %v", pol, err)
	}

	if err := repo.UpsertGucBaseline(ctx, "global", map[string]string{"shared_buffers": "128MB"}); err != nil {
		t.Fatalf("UpsertGucBaseline: %v", err)
	}
	label, settings, _, err := repo.GetGucBaseline(ctx)
	if err != nil || label == "" || settings["shared_buffers"] != "128MB" {
		t.Fatalf("GetGucBaseline: %s %+v %v", label, settings, err)
	}
	gucTID := reportstore.GucTargetID(pg)
	if err := repo.UpsertServerGucSnapshot(ctx, gucTID, "parity-host", "node-1", map[string]string{"work_mem": "4MB"}); err != nil {
		t.Fatalf("UpsertServerGucSnapshot: %v", err)
	}
	snaps, err := repo.ListServerGucSnapshots(ctx)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("ListServerGucSnapshots: %d %v", len(snaps), err)
	}
	if err := repo.UpsertGucIgnore(ctx, reportstore.GucIgnoreScopeHost, gucTID, ""); err != nil {
		t.Fatalf("UpsertGucIgnore: %v", err)
	}
	ignores, err := repo.ListGucIgnores(ctx)
	if err != nil || len(ignores) == 0 {
		t.Fatalf("ListGucIgnores: %d %v", len(ignores), err)
	}
	gid, err := repo.UpsertGucServerGroup(ctx, "", "parity-group", "test", map[string]string{})
	if err != nil || gid == "" {
		t.Fatalf("UpsertGucServerGroup: %s %v", gid, err)
	}
	if err := repo.SetGucServerGroupMembers(ctx, gid, []string{gucTID}); err != nil {
		t.Fatalf("SetGucServerGroupMembers: %v", err)
	}
	grp, err := repo.GetGucServerGroup(ctx, gid)
	if err != nil || grp == nil || len(grp.MemberIDs) != 1 {
		t.Fatalf("GetGucServerGroup: %+v %v", grp, err)
	}

	now := time.Now().UTC()
	if err := repo.UpsertCollectorStatus(ctx, "node-1", "parity-host", "127.0.0.1", now, true, 2, ""); err != nil {
		t.Fatalf("UpsertCollectorStatus: %v", err)
	}
	if err := repo.InsertCollectorRun(ctx, "node-1", "parity-host", "cron", now, now, []string{"all"}, true, ""); err != nil {
		t.Fatalf("InsertCollectorRun: %v", err)
	}
	if err := repo.InsertCollectorActivity(ctx, "node-1", "scan", "ok", "info", now); err != nil {
		t.Fatalf("InsertCollectorActivity: %v", err)
	}
	if err := repo.InsertCollectorLog(ctx, "node-1", "info", "hello", now); err != nil {
		t.Fatalf("InsertCollectorLog: %v", err)
	}
	nodes, err := repo.ListCollectorNodes(ctx)
	if err != nil || len(nodes) == 0 {
		t.Fatalf("ListCollectorNodes: %d %v", len(nodes), err)
	}
	runs2, err := repo.ListCollectorRuns(ctx, "node-1", 10)
	if err != nil || len(runs2) == 0 {
		t.Fatalf("ListCollectorRuns: %d %v", len(runs2), err)
	}
}
