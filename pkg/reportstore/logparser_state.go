package reportstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/logparser/aggregation"
)

// LogParserInactiveUserState is aggregated inactive user state for one target.
type LogParserInactiveUserState struct {
	TargetID      string
	TargetHost    string
	User          string
	InactiveSince time.Time
	UpdatedAt     time.Time
}

// LogParserUnusedHBAState is aggregated unused HBA line state for one target.
type LogParserUnusedHBAState struct {
	TargetID    string
	TargetHost  string
	EntityKey   string
	LineNo      string
	LineText    string
	UnusedSince time.Time
	UpdatedAt   time.Time
}

// LogParserClientIPState is accumulated client IP state for one target.
type LogParserClientIPState struct {
	TargetID   string
	TargetHost string
	IP         string
	FirstSeen  time.Time
	UpdatedAt  time.Time
}

const logParserStateSchema = `
CREATE TABLE IF NOT EXISTS logparser_inactive_users (
	target_id TEXT NOT NULL,
	target_host TEXT NOT NULL DEFAULT '',
	entity_key TEXT NOT NULL,
	inactive_since TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (target_id, entity_key)
);
CREATE INDEX IF NOT EXISTS idx_logparser_inactive_users_target ON logparser_inactive_users(target_id);
CREATE TABLE IF NOT EXISTS logparser_unused_hba (
	target_id TEXT NOT NULL,
	target_host TEXT NOT NULL DEFAULT '',
	entity_key TEXT NOT NULL,
	line_no TEXT NOT NULL DEFAULT '',
	line_text TEXT NOT NULL DEFAULT '',
	unused_since TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (target_id, entity_key)
);
CREATE INDEX IF NOT EXISTS idx_logparser_unused_hba_target ON logparser_unused_hba(target_id);
CREATE TABLE IF NOT EXISTS logparser_client_ips (
	target_id TEXT NOT NULL,
	target_host TEXT NOT NULL DEFAULT '',
	entity_key TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (target_id, entity_key)
);
CREATE INDEX IF NOT EXISTS idx_logparser_client_ips_target ON logparser_client_ips(target_id);
`

func ensureLogParserStateSchema(ctx context.Context, db *sql.DB) error {
	for _, stmt := range splitSQLStatements(logParserStateSchema) {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, rebindSQL(db, stmt)); err != nil {
			return err
		}
	}
	return nil
}

// postgresText stores a string in a PostgreSQL text column. PostgreSQL rejects
// U+0000, and the unused-HBA entity key uses that byte as its separator.
// U+2400 stands in for it and is restored on read. SQLite keeps the original byte.
func postgresText(s string) string {
	if !UsePostgresPlaceholders || !strings.Contains(s, "\x00") {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "\u2400")
}

func postgresTextFromDB(s string) string {
	if !UsePostgresPlaceholders || !strings.Contains(s, "\u2400") {
		return s
	}
	return strings.ReplaceAll(s, "\u2400", "\x00")
}

func splitSQLStatements(batch string) []string {
	var out []string
	for _, part := range strings.Split(batch, ";") {
		s := strings.TrimSpace(part)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// UpdateLogParserStateFromReport merges scan output into aggregation tables.
func UpdateLogParserStateFromReport(ctx context.Context, db *sql.DB, targetID, targetHost string,
	report map[string]interface{}, at time.Time) error {
	if db == nil || targetID == "" || report == nil {
		return nil
	}
	if err := ensureLogParserStateSchema(ctx, db); err != nil {
		return fmt.Errorf("logparser state schema: %w", err)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	targetHost = strings.TrimSpace(targetHost)

	inactive := aggregation.InactiveUsersFromReport(report)
	if aggregation.ShouldApplyScanSnapshot(report, cons.LogParserCMD_InactiveUser, len(inactive) > 0) {
		if err := mergeInactiveUsers(ctx, db, targetID, targetHost, inactive, at); err != nil {
			return err
		}
	}
	ips := aggregation.ClientIPsFromReport(report)
	if aggregation.ShouldApplyScanSnapshot(report, cons.LogParserCMD_UniqueIPs, len(ips) > 0) {
		if err := mergeClientIPs(ctx, db, targetID, targetHost, ips, at); err != nil {
			return err
		}
	}
	lines := aggregation.UnusedHBALinesFromReport(report)
	if aggregation.ShouldApplyScanSnapshot(report, cons.LogParserCMD_HBAUnusedLines, len(lines) > 0) {
		if err := mergeUnusedHBALines(ctx, db, targetID, targetHost, lines, at); err != nil {
			return err
		}
	}
	return nil
}

func mergeInactiveUsers(ctx context.Context, db *sql.DB, targetID, targetHost string, current []string, at time.Time) error {
	prev, err := loadInactiveSinceMap(ctx, db, targetID)
	if err != nil {
		return err
	}
	next := aggregation.MergeSinceSet(prev, current, at)
	return replaceInactiveUsers(ctx, db, targetID, targetHost, next, at)
}

func mergeClientIPs(ctx context.Context, db *sql.DB, targetID, targetHost string, current []string, at time.Time) error {
	prev, err := loadClientIPSinceMap(ctx, db, targetID)
	if err != nil {
		return err
	}
	next := aggregation.MergeAccumulateSet(prev, current, at)
	return replaceClientIPs(ctx, db, targetID, targetHost, next, at)
}

func mergeUnusedHBALines(ctx context.Context, db *sql.DB, targetID, targetHost string, current []aggregation.UnusedHBALine, at time.Time) error {
	prev, err := loadUnusedSinceMap(ctx, db, targetID)
	if err != nil {
		return err
	}
	keys := aggregation.EntityKeysForUnusedLines(current)
	next := aggregation.MergeSinceSet(prev, keys, at)
	return replaceUnusedHBALines(ctx, db, targetID, targetHost, current, next, at)
}

func loadInactiveSinceMap(ctx context.Context, db *sql.DB, targetID string) (map[string]time.Time, error) {
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT entity_key, inactive_since FROM logparser_inactive_users WHERE target_id = ?`), targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var key, since string
		if err := rows.Scan(&key, &since); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			continue
		}
		out[postgresTextFromDB(key)] = t.UTC()
	}
	return out, rows.Err()
}

func loadClientIPSinceMap(ctx context.Context, db *sql.DB, targetID string) (map[string]time.Time, error) {
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT entity_key, first_seen FROM logparser_client_ips WHERE target_id = ?`), targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var key, since string
		if err := rows.Scan(&key, &since); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			continue
		}
		out[postgresTextFromDB(key)] = t.UTC()
	}
	return out, rows.Err()
}

func loadUnusedSinceMap(ctx context.Context, db *sql.DB, targetID string) (map[string]time.Time, error) {
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT entity_key, unused_since FROM logparser_unused_hba WHERE target_id = ?`), targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var key, since string
		if err := rows.Scan(&key, &since); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			continue
		}
		out[postgresTextFromDB(key)] = t.UTC()
	}
	return out, rows.Err()
}

func replaceInactiveUsers(ctx context.Context, db *sql.DB, targetID, targetHost string, next map[string]time.Time, at time.Time) error {
	return execInTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, rebindSQL(db, `DELETE FROM logparser_inactive_users WHERE target_id = ?`), targetID); err != nil {
			return err
		}
		updated := at.UTC().Format(time.RFC3339)
		for user, since := range next {
			if _, err := tx.ExecContext(ctx, rebindSQL(db, `
				INSERT INTO logparser_inactive_users (target_id, target_host, entity_key, inactive_since, updated_at)
				VALUES (?, ?, ?, ?, ?)`),
				targetID, postgresText(targetHost), postgresText(user), since.UTC().Format(time.RFC3339), updated); err != nil {
				return err
			}
		}
		return nil
	})
}

func replaceClientIPs(ctx context.Context, db *sql.DB, targetID, targetHost string, next map[string]time.Time, at time.Time) error {
	return execInTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, rebindSQL(db, `DELETE FROM logparser_client_ips WHERE target_id = ?`), targetID); err != nil {
			return err
		}
		updated := at.UTC().Format(time.RFC3339)
		for ip, since := range next {
			if _, err := tx.ExecContext(ctx, rebindSQL(db, `
				INSERT INTO logparser_client_ips (target_id, target_host, entity_key, first_seen, updated_at)
				VALUES (?, ?, ?, ?, ?)`),
				targetID, postgresText(targetHost), postgresText(ip), since.UTC().Format(time.RFC3339), updated); err != nil {
				return err
			}
		}
		return nil
	})
}

func replaceUnusedHBALines(ctx context.Context, db *sql.DB, targetID, targetHost string,
	current []aggregation.UnusedHBALine, next map[string]time.Time, at time.Time) error {
	lineMeta := map[string]aggregation.UnusedHBALine{}
	for _, l := range current {
		lineMeta[l.LineNo+"\x00"+l.Line] = l
	}
	// Preserve line text from DB for lines still unused but missing from this scan's detail payload.
	existing, _ := listUnusedHBALinesForTarget(ctx, db, targetID)
	for _, row := range existing {
		if _, ok := next[row.EntityKey]; ok {
			if _, ok := lineMeta[row.EntityKey]; !ok {
				lineMeta[row.EntityKey] = aggregation.UnusedHBALine{LineNo: row.LineNo, Line: row.LineText}
			}
		}
	}
	return execInTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, rebindSQL(db, `DELETE FROM logparser_unused_hba WHERE target_id = ?`), targetID); err != nil {
			return err
		}
		updated := at.UTC().Format(time.RFC3339)
		for key, since := range next {
			meta := lineMeta[key]
			if parts := strings.SplitN(key, "\x00", 2); len(parts) == 2 && meta.LineNo == "" && meta.Line == "" {
				meta.LineNo, meta.Line = parts[0], parts[1]
			}
			if _, err := tx.ExecContext(ctx, rebindSQL(db, `
				INSERT INTO logparser_unused_hba (target_id, target_host, entity_key, line_no, line_text, unused_since, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`),
				targetID, postgresText(targetHost), postgresText(key), postgresText(meta.LineNo), postgresText(meta.Line), since.UTC().Format(time.RFC3339), updated); err != nil {
				return err
			}
		}
		return nil
	})
}

func execInTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func listUnusedHBALinesForTarget(ctx context.Context, db *sql.DB, targetID string) ([]LogParserUnusedHBAState, error) {
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT target_id, target_host, entity_key, line_no, line_text, unused_since, updated_at
		FROM logparser_unused_hba WHERE target_id = ?`), targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUnusedHBARows(rows)
}

// ListLogParserInactiveUsers returns fleet-wide inactive user aggregation.
func ListLogParserInactiveUsers(ctx context.Context, db *sql.DB) ([]LogParserInactiveUserState, error) {
	if err := ensureLogParserStateSchema(ctx, db); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT target_id, target_host, entity_key, inactive_since, updated_at
		FROM logparser_inactive_users ORDER BY target_id, entity_key`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogParserInactiveUserState
	for rows.Next() {
		var targetID, host, user, since, updated string
		if err := rows.Scan(&targetID, &host, &user, &since, &updated); err != nil {
			return nil, err
		}
		sinceT, _ := time.Parse(time.RFC3339, since)
		updatedT, _ := time.Parse(time.RFC3339, updated)
		out = append(out, LogParserInactiveUserState{
			TargetID: targetID, TargetHost: postgresTextFromDB(host), User: postgresTextFromDB(user),
			InactiveSince: sinceT.UTC(), UpdatedAt: updatedT.UTC(),
		})
	}
	return out, rows.Err()
}

// ListLogParserClientIPs returns fleet-wide accumulated client IPs.
func ListLogParserClientIPs(ctx context.Context, db *sql.DB) ([]LogParserClientIPState, error) {
	if err := ensureLogParserStateSchema(ctx, db); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT target_id, target_host, entity_key, first_seen, updated_at
		FROM logparser_client_ips ORDER BY target_id, entity_key`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogParserClientIPState
	for rows.Next() {
		var targetID, host, ip, first, updated string
		if err := rows.Scan(&targetID, &host, &ip, &first, &updated); err != nil {
			return nil, err
		}
		firstT, _ := time.Parse(time.RFC3339, first)
		updatedT, _ := time.Parse(time.RFC3339, updated)
		out = append(out, LogParserClientIPState{
			TargetID: targetID, TargetHost: postgresTextFromDB(host), IP: postgresTextFromDB(ip),
			FirstSeen: firstT.UTC(), UpdatedAt: updatedT.UTC(),
		})
	}
	return out, rows.Err()
}

// ListLogParserUnusedHBALines returns fleet-wide unused HBA aggregation.
func ListLogParserUnusedHBALines(ctx context.Context, db *sql.DB) ([]LogParserUnusedHBAState, error) {
	if err := ensureLogParserStateSchema(ctx, db); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, rebindSQL(db, `
		SELECT target_id, target_host, entity_key, line_no, line_text, unused_since, updated_at
		FROM logparser_unused_hba ORDER BY target_id, entity_key`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUnusedHBARows(rows)
}

func scanUnusedHBARows(rows *sql.Rows) ([]LogParserUnusedHBAState, error) {
	var out []LogParserUnusedHBAState
	for rows.Next() {
		var targetID, host, key, lineNo, lineText, since, updated string
		if err := rows.Scan(&targetID, &host, &key, &lineNo, &lineText, &since, &updated); err != nil {
			return nil, err
		}
		sinceT, _ := time.Parse(time.RFC3339, since)
		updatedT, _ := time.Parse(time.RFC3339, updated)
		out = append(out, LogParserUnusedHBAState{
			TargetID: targetID, TargetHost: postgresTextFromDB(host), EntityKey: postgresTextFromDB(key),
			LineNo: postgresTextFromDB(lineNo), LineText: postgresTextFromDB(lineText),
			UnusedSince: sinceT.UTC(), UpdatedAt: updatedT.UTC(),
		})
	}
	return out, rows.Err()
}
