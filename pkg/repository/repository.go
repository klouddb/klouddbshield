package repository

import (
	"context"
	"time"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/repository/rows"
)

// CollectorNodeRow is a fleet node status record.
type CollectorNodeRow = rows.CollectorNodeRow

// CollectorRunRow is one collector execution record.
type CollectorRunRow = rows.CollectorRunRow

// CollectorActivityRow is a collector activity event.
type CollectorActivityRow = rows.CollectorActivityRow

// CollectorLogRow is a collector log line.
type CollectorLogRow = rows.CollectorLogRow

// Repository is the storage abstraction for the main-server.
type Repository interface {
	Ping(ctx context.Context) error
	Close() error
	EnsureSchema(ctx context.Context) error

	PersistScanResult(ctx context.Context, fileData map[string]interface{}, meta reportstore.ScanResultMeta) (string, error)
	PersistPIIReport(ctx context.Context, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error
	PersistBackupComplianceReport(ctx context.Context, meta reportstore.BackupComplianceReportMeta, reportJSON map[string]interface{}) error
	GetLatestRun(ctx context.Context, targetID string) (*reportstore.RunRow, error)
	GetLatestRunWithPII(ctx context.Context, targetID string) (*reportstore.RunRow, error)
	ListLatestBackupComplianceReports(ctx context.Context) ([]reportstore.BackupComplianceRow, error)
	GetLatestRunWithBackupCompliance(ctx context.Context, targetID string) (*reportstore.BackupComplianceRow, error)
	GetRunByID(ctx context.Context, id string) (*reportstore.RunRow, error)
	GetRuns(ctx context.Context, limit int) ([]reportstore.RunRow, error)
	ListRunTargetIDs(ctx context.Context) ([]string, error)
	GetRunsForTarget(ctx context.Context, targetID string, limit int) ([]reportstore.RunRow, error)

	UpsertGucBaseline(ctx context.Context, label string, settings map[string]string) error
	GetGucBaseline(ctx context.Context) (label string, settings map[string]string, updatedAt string, err error)
	UpsertServerGucSnapshot(ctx context.Context, targetID, targetHost, nodeID string, settings map[string]string) error
	GetServerGucSnapshot(ctx context.Context, targetID string) (map[string]string, string, string, error)
	ListServerGucSnapshots(ctx context.Context) ([]reportstore.GucSnapshotSummary, error)

	UpsertGucIgnore(ctx context.Context, scope, targetID, gucName string) error
	DeleteGucIgnore(ctx context.Context, scope, targetID, gucName string) error
	ListGucIgnores(ctx context.Context) ([]reportstore.GucIgnoreEntry, error)

	UpsertGucServerGroup(ctx context.Context, id, name, description string, baseline map[string]string) (string, error)
	DeleteGucServerGroup(ctx context.Context, id string) error
	GetGucServerGroup(ctx context.Context, id string) (*reportstore.GucServerGroup, error)
	ListGucServerGroups(ctx context.Context) ([]reportstore.GucServerGroup, error)
	SetGucServerGroupMembers(ctx context.Context, groupID string, targetIDs []string) error
	SetGucServerGroupBaseline(ctx context.Context, groupID string, baseline map[string]string) error

	UpsertBackupCompliancePolicy(ctx context.Context, policy reportstore.BackupCompliancePolicyStored) error
	GetBackupCompliancePolicy(ctx context.Context) (policy reportstore.BackupCompliancePolicyStored, updatedAt string, err error)

	UpsertCollectorStatus(ctx context.Context, nodeID, hostname, ip string, ts time.Time, cronRunning bool, scheduledJobs int, lastError string) error
	InsertCollectorActivity(ctx context.Context, nodeID, kind, message, level string, ts time.Time) error
	TouchCollectorLastSeen(ctx context.Context, nodeID string, ts time.Time) error
	InsertCollectorLog(ctx context.Context, nodeID, level, message string, ts time.Time) error
	InsertCollectorRun(ctx context.Context, nodeID, hostname string, trigger string, startedAt, finishedAt time.Time, features []string, success bool, errMsg string) error
	ListCollectorNodes(ctx context.Context) ([]CollectorNodeRow, error)
	GetCollectorNode(ctx context.Context, nodeID string) (*CollectorNodeRow, error)
	ListCollectorRuns(ctx context.Context, nodeID string, limit int) ([]CollectorRunRow, error)
	ListCollectorActivity(ctx context.Context, nodeID string, limit int) ([]CollectorActivityRow, error)
	ListCollectorLogs(ctx context.Context, nodeID string, limit int) ([]CollectorLogRow, error)
}
