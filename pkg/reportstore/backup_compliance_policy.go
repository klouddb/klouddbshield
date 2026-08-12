package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const backupCompliancePolicyRowID = "global"

// BackupCompliancePolicyStored is the dashboard-saved authorized window.
type BackupCompliancePolicyStored struct {
	AllowedStart string   `json:"allowed_start"`
	AllowedEnd   string   `json:"allowed_end"`
	AllowedDays  []string `json:"allowed_days,omitempty"`
	Timezone     string   `json:"timezone,omitempty"`
}

// UpsertBackupCompliancePolicy stores the fleet-wide dashboard backup window.
func UpsertBackupCompliancePolicy(ctx context.Context, db *sql.DB, policy BackupCompliancePolicyStored) error {
	policy.AllowedStart = strings.TrimSpace(policy.AllowedStart)
	policy.AllowedEnd = strings.TrimSpace(policy.AllowedEnd)
	policy.Timezone = strings.TrimSpace(policy.Timezone)
	days := make([]string, 0, len(policy.AllowedDays))
	for _, d := range policy.AllowedDays {
		d = strings.TrimSpace(d)
		if d != "" {
			days = append(days, d)
		}
	}
	policy.AllowedDays = days
	blob, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal backup compliance policy: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.ExecContext(ctx, `
		INSERT INTO backup_compliance_policy (id, policy_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			policy_json = excluded.policy_json,
			updated_at = excluded.updated_at
	`, backupCompliancePolicyRowID, string(blob), now)
	return err
}

// GetBackupCompliancePolicy returns the dashboard-saved window (empty if unset).
func GetBackupCompliancePolicy(ctx context.Context, db *sql.DB) (policy BackupCompliancePolicyStored, updatedAt string, err error) {
	var blob string
	err = db.QueryRowContext(ctx, `
		SELECT policy_json, updated_at FROM backup_compliance_policy WHERE id = ?
	`, backupCompliancePolicyRowID).Scan(&blob, &updatedAt)
	if err == sql.ErrNoRows {
		return BackupCompliancePolicyStored{AllowedDays: []string{}}, "", nil
	}
	if err != nil {
		return BackupCompliancePolicyStored{}, "", err
	}
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &policy); err != nil {
			return BackupCompliancePolicyStored{}, "", fmt.Errorf("decode backup compliance policy: %w", err)
		}
	}
	if policy.AllowedDays == nil {
		policy.AllowedDays = []string{}
	}
	return policy, updatedAt, nil
}
