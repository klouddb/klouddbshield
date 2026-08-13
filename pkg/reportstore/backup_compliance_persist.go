package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// BackupComplianceReportMeta identifies who ran the backup compliance scan.
type BackupComplianceReportMeta struct {
	NodeID   string
	Hostname string
	Trigger  string // cron | manual
	Postgres *postgresdb.Postgres
}

// PersistBackupComplianceReport inserts a new scan_results/runs row every scan.
// Previous reports are kept; the dashboard reads the latest row per target only
// (so KPIs are not double-counted across scan history).
func PersistBackupComplianceReport(ctx context.Context, db *sql.DB, meta BackupComplianceReportMeta, reportJSON map[string]interface{}) error {
	if meta.Postgres == nil {
		return fmt.Errorf("postgres config is required")
	}
	if reportJSON == nil {
		reportJSON = map[string]interface{}{}
	}
	blob, err := encodeReport(reportJSON)
	if err != nil {
		return err
	}
	tid := TargetID(meta.Postgres)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return insertBackupComplianceOnlyRun(ctx, db, meta, tid, blob, now)
}

func insertBackupComplianceOnlyRun(ctx context.Context, db *sql.DB, meta BackupComplianceReportMeta, tid string, blob []byte, scannedAt string) error {
	id := uuid.NewString()
	now := time.Now().UTC()
	started := now.Format(time.RFC3339Nano)
	host, port, dbName := targetFields(meta.Postgres)
	nodeID := strings.TrimSpace(meta.NodeID)
	if nodeID == "" {
		nodeID = "backup-compliance-scan"
	}
	hostname := strings.TrimSpace(meta.Hostname)
	if hostname == "" {
		hostname = host
	}
	featuresJSON, _ := json.Marshal([]string{cons.RootCMD_BackupCompliance})
	emptyReport := []byte(`{}`)
	trigger := strings.TrimSpace(meta.Trigger)
	if trigger == "" {
		trigger = "cron"
	}

	return execWithRetry(ctx, 30, func() error {
		if RunsTable == "scan_results" {
			return insertScanResultImmediate(ctx, db,
				id, nodeID, hostname,
				started, started,
				trigger, "ciscollector",
				"postgres", tid, host, port, dbName,
				"success", string(featuresJSON), 0, 0, 0, emptyReport,
				nil, nil,
				blob, scannedAt,
				"",
			)
		}
		return insertRunImmediate(ctx, db,
			id, started, started,
			trigger, "ciscollector",
			"postgres", tid, host, port, dbName,
			"success", string(featuresJSON), 0, 0, 0, emptyReport,
			nil, nil,
			blob, scannedAt,
		)
	})
}
