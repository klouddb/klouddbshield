package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GucServerGroup is a named set of hosts with an optional per-group baseline.
type GucServerGroup struct {
	ID          string
	Name        string
	Description string
	Baseline    map[string]string
	UpdatedAt   string
	MemberIDs   []string
}

// UpsertGucServerGroup creates or updates a server group (baseline optional).
func UpsertGucServerGroup(ctx context.Context, db *sql.DB, id, name, description string, baseline map[string]string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if id == "" {
		id = uuid.NewString()
	}
	if baseline == nil {
		baseline = map[string]string{}
	}
	blob, err := json.Marshal(baseline)
	if err != nil {
		return "", fmt.Errorf("marshal baseline: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.ExecContext(ctx, `
		INSERT INTO guc_server_groups (id, name, description, baseline_json, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			baseline_json = excluded.baseline_json,
			updated_at = excluded.updated_at
	`, id, name, strings.TrimSpace(description), string(blob), now)
	if err != nil {
		return "", err
	}
	return id, nil
}

// DeleteGucServerGroup removes a group and its members.
func DeleteGucServerGroup(ctx context.Context, db *sql.DB, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM guc_server_group_members WHERE group_id = ?`, id); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `DELETE FROM guc_server_groups WHERE id = ?`, id)
	return err
}

// GetGucServerGroup returns one group with members.
func GetGucServerGroup(ctx context.Context, db *sql.DB, id string) (*GucServerGroup, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, nil
	}
	var g GucServerGroup
	var blob string
	err := db.QueryRowContext(ctx, `
		SELECT id, name, description, baseline_json, updated_at
		FROM guc_server_groups WHERE id = ?
	`, id).Scan(&g.ID, &g.Name, &g.Description, &blob, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g.Baseline = map[string]string{}
	if blob != "" {
		_ = json.Unmarshal([]byte(blob), &g.Baseline)
	}
	members, err := ListGucServerGroupMembers(ctx, db, id)
	if err != nil {
		return nil, err
	}
	g.MemberIDs = members
	return &g, nil
}

// ListGucServerGroups returns all groups (with members).
func ListGucServerGroups(ctx context.Context, db *sql.DB) ([]GucServerGroup, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, description, baseline_json, updated_at
		FROM guc_server_groups
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []GucServerGroup
	for rows.Next() {
		var g GucServerGroup
		var blob string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &blob, &g.UpdatedAt); err != nil {
			return nil, err
		}
		g.Baseline = map[string]string{}
		if blob != "" {
			_ = json.Unmarshal([]byte(blob), &g.Baseline)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		members, err := ListGucServerGroupMembers(ctx, db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].MemberIDs = members
	}
	return out, nil
}

// ListGucServerGroupMembers returns target_ids in a group.
func ListGucServerGroupMembers(ctx context.Context, db *sql.DB, groupID string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT target_id FROM guc_server_group_members
		WHERE group_id = ?
		ORDER BY target_id ASC
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetGucServerGroupMembers replaces membership for a group.
func SetGucServerGroupMembers(ctx context.Context, db *sql.DB, groupID string, targetIDs []string) error {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return fmt.Errorf("group_id is required")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM guc_server_group_members WHERE group_id = ?`, groupID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, tid := range targetIDs {
		tid = strings.TrimSpace(tid)
		if tid == "" || seen[tid] {
			continue
		}
		seen[tid] = true
		if _, err := db.ExecContext(ctx, `
			INSERT INTO guc_server_group_members (group_id, target_id) VALUES (?, ?)
		`, groupID, tid); err != nil {
			return err
		}
	}
	return nil
}

// SetGucServerGroupBaseline stores host-ref or file baseline metadata for a group.
func SetGucServerGroupBaseline(ctx context.Context, db *sql.DB, groupID string, baseline map[string]string) error {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return fmt.Errorf("group_id is required")
	}
	if baseline == nil {
		baseline = map[string]string{}
	}
	blob, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.ExecContext(ctx, `
		UPDATE guc_server_groups SET baseline_json = ?, updated_at = ? WHERE id = ?
	`, string(blob), now, groupID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}
