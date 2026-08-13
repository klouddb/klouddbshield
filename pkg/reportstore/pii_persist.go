package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// PersistPIIReport writes only pii_report_json and pii_scanned_at for the latest run of target_id.
// report_json is never read or modified.
func PersistPIIReport(ctx context.Context, db *sql.DB, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error {
	if pg == nil {
		return fmt.Errorf("postgres config is required")
	}
	if piiJSON == nil {
		piiJSON = map[string]interface{}{}
	}
	blob, err := encodeReport(piiJSON)
	if err != nil {
		return err
	}
	tid := TargetID(pg)
	now := time.Now().UTC().Format(time.RFC3339)
	table := RunsTable

	var existingID, existingFeatures sql.NullString
	err = db.QueryRowContext(ctx, `
		SELECT id, features_run FROM `+table+`
		WHERE target_id = ?
		ORDER BY started_at DESC LIMIT 1
	`, tid).Scan(&existingID, &existingFeatures)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup run: %w", err)
	}

	if existingID.Valid && existingID.String != "" {
		features := mergeFeaturesRun(existingFeatures.String, cons.RootCMD_PiiScanner)
		return execWithRetry(ctx, 30, func() error {
			_, err := db.ExecContext(ctx, `
				UPDATE `+table+` SET pii_report_json = ?, pii_scanned_at = ?, features_run = ?
				WHERE id = ?
			`, string(blob), now, features, existingID.String)
			return err
		})
	}

	return insertPIIOnlyRun(ctx, db, pg, tid, blob, now)
}

func mergeFeaturesRun(existingJSON, feature string) string {
	var features []string
	if existingJSON != "" {
		_ = json.Unmarshal([]byte(existingJSON), &features)
	}
	for _, f := range features {
		if f == feature {
			return existingJSON
		}
	}
	features = append(features, feature)
	out, _ := json.Marshal(features)
	return string(out)
}

func insertPIIOnlyRun(ctx context.Context, db *sql.DB, pg *postgresdb.Postgres, tid string, piiBlob []byte, scannedAt string) error {
	id := uuid.NewString()
	now := time.Now().UTC()
	started := now.Format(time.RFC3339)
	finished := started
	host, port, dbName := targetFields(pg)
	featuresJSON, _ := json.Marshal([]string{cons.RootCMD_PiiScanner})
	emptyReport := []byte(`{}`)

	return execWithRetry(ctx, 30, func() error {
		if RunsTable == "scan_results" {
			return insertScanResultImmediate(ctx, db,
				id, "pii-scan", host,
				started, finished,
				"manual", "ciscollector",
				"postgres", tid, host, port, dbName,
				"success", string(featuresJSON), 0, 0, 0, emptyReport,
				piiBlob, scannedAt,
				nil, nil,
				"",
			)
		}
		return insertRunImmediate(ctx, db,
			id, started, finished,
			"manual", "ciscollector",
			"postgres", tid, host, port, dbName,
			"success", string(featuresJSON), 0, 0, 0, emptyReport,
			piiBlob, scannedAt,
			nil, nil,
		)
	})
}
