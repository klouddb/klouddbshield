package reportstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	GucIgnoreScopeHost = "host"
	GucIgnoreScopeGuc  = "guc"
)

// GucIgnoreEntry is one ignored host or GUC finding.
type GucIgnoreEntry struct {
	ID          string
	Scope       string
	TargetID    string
	InstanceKey string
	GucName     string
	IgnoredAt   string
}

func gucIgnoreID(scope, instanceKey, gucName string) string {
	gucName = strings.ToLower(strings.TrimSpace(gucName))
	base := scope + "|" + instanceKey
	if scope == GucIgnoreScopeGuc {
		base += "|" + gucName
	}
	return base
}

// UpsertGucIgnore stores a host-level or GUC-level ignore.
func UpsertGucIgnore(ctx context.Context, db *sql.DB, scope, targetID, gucName string) error {
	scope = strings.TrimSpace(strings.ToLower(scope))
	targetID = strings.TrimSpace(targetID)
	gucName = strings.ToLower(strings.TrimSpace(gucName))
	if scope != GucIgnoreScopeHost && scope != GucIgnoreScopeGuc {
		return fmt.Errorf("scope must be host or guc")
	}
	if targetID == "" {
		return fmt.Errorf("target_id is required")
	}
	if scope == GucIgnoreScopeGuc && gucName == "" {
		return fmt.Errorf("guc is required for guc-scope ignore")
	}
	if scope == GucIgnoreScopeHost {
		gucName = ""
	}
	instanceKey := GucInstanceKey(targetID)
	if instanceKey == "" {
		instanceKey = targetID
	}
	id := gucIgnoreID(scope, instanceKey, gucName)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.ExecContext(ctx, `
		INSERT INTO guc_drift_ignores (id, scope, target_id, instance_key, guc_name, ignored_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			target_id = excluded.target_id,
			ignored_at = excluded.ignored_at
	`, id, scope, targetID, instanceKey, gucName, now)
	return err
}

// DeleteGucIgnore removes a host-level or GUC-level ignore.
func DeleteGucIgnore(ctx context.Context, db *sql.DB, scope, targetID, gucName string) error {
	scope = strings.TrimSpace(strings.ToLower(scope))
	targetID = strings.TrimSpace(targetID)
	gucName = strings.ToLower(strings.TrimSpace(gucName))
	if scope == GucIgnoreScopeHost {
		gucName = ""
	}
	instanceKey := GucInstanceKey(targetID)
	if instanceKey == "" {
		instanceKey = targetID
	}
	id := gucIgnoreID(scope, instanceKey, gucName)
	_, err := db.ExecContext(ctx, `DELETE FROM guc_drift_ignores WHERE id = ?`, id)
	return err
}

// ListGucIgnores returns all active ignores.
func ListGucIgnores(ctx context.Context, db *sql.DB) ([]GucIgnoreEntry, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, scope, target_id, instance_key, guc_name, ignored_at
		FROM guc_drift_ignores
		ORDER BY ignored_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GucIgnoreEntry
	for rows.Next() {
		var e GucIgnoreEntry
		if err := rows.Scan(&e.ID, &e.Scope, &e.TargetID, &e.InstanceKey, &e.GucName, &e.IgnoredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GucIgnoreIndex indexes ignores for fast drift filtering.
type GucIgnoreIndex struct {
	Hosts map[string]bool            // instance_key
	Gucs  map[string]map[string]bool // instance_key -> guc_name
}

// BuildGucIgnoreIndex loads all ignores into lookup maps.
func BuildGucIgnoreIndex(entries []GucIgnoreEntry) GucIgnoreIndex {
	idx := GucIgnoreIndex{
		Hosts: map[string]bool{},
		Gucs:  map[string]map[string]bool{},
	}
	for _, e := range entries {
		key := e.InstanceKey
		if key == "" {
			key = GucInstanceKey(e.TargetID)
		}
		if key == "" {
			continue
		}
		switch e.Scope {
		case GucIgnoreScopeHost:
			idx.Hosts[key] = true
		case GucIgnoreScopeGuc:
			guc := strings.ToLower(strings.TrimSpace(e.GucName))
			if guc == "" {
				continue
			}
			if idx.Gucs[key] == nil {
				idx.Gucs[key] = map[string]bool{}
			}
			idx.Gucs[key][guc] = true
		}
	}
	return idx
}

// HostIgnored reports whether the instance is host-level ignored.
func (idx GucIgnoreIndex) HostIgnored(targetID string) bool {
	key := GucInstanceKey(targetID)
	if key == "" {
		key = strings.TrimSpace(targetID)
	}
	return idx.Hosts[key]
}

// GucIgnored reports whether a specific GUC finding is ignored for the instance.
func (idx GucIgnoreIndex) GucIgnored(targetID, gucName string) bool {
	key := GucInstanceKey(targetID)
	if key == "" {
		key = strings.TrimSpace(targetID)
	}
	guc := strings.ToLower(strings.TrimSpace(gucName))
	if key == "" || guc == "" {
		return false
	}
	return idx.Gucs[key][guc]
}
