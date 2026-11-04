package reportstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PurgeRetention deletes runs older than retentionDays. No-op if retentionDays <= 0.
func PurgeRetention(ctx context.Context, db *sql.DB, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	res, err := execContext(ctx, db, `DELETE FROM `+RunsTable+` WHERE started_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge runs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
