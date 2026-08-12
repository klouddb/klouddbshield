package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	reprows "github.com/klouddb/klouddbshield/pkg/repository/rows"
)

const runsTable = "scan_results"
const gucBaselineRowID = "global"

// Repository implements repository.Repository using PostgreSQL.
type Repository struct {
	db *sql.DB
}

// Open connects to PostgreSQL and ensures schema.
func Open(ctx context.Context, url string) (*Repository, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	repo := &Repository{db: db}
	if err := repo.EnsureSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return repo, nil
}

func (r *Repository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *Repository) Close() error {
	return r.db.Close()
}

func (r *Repository) exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return r.db.ExecContext(ctx, rebindPostgres(query), args...)
}

func (r *Repository) query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, rebindPostgres(query), args...)
}

func (r *Repository) queryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return r.db.QueryRowContext(ctx, rebindPostgres(query), args...)
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	for _, stmt := range schemaStatements() {
		if _, err := r.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("postgres schema: %w", err)
		}
	}
	return nil
}

func (r *Repository) PersistScanResult(ctx context.Context, fileData map[string]interface{}, meta reportstore.ScanResultMeta) (string, error) {
	if fileData == nil {
		fileData = map[string]interface{}{}
	}
	blob, err := encodeReport(fileData)
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	started := meta.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	finished := meta.FinishedAt
	if finished.IsZero() {
		finished = time.Now().UTC()
	}
	trigger := meta.Trigger
	if trigger == "" {
		trigger = "cron"
	}
	status := meta.RunStatus
	if status == "" {
		status = "success"
	}
	if meta.ErrorMessage != "" {
		status = "failed"
	}
	featuresJSON, _ := json.Marshal(meta.FeaturesRun)
	host, port, dbName := targetFields(meta.Postgres)
	tid := reportstore.TargetID(meta.Postgres)
	pass, fail, score := summarizeFromReport(fileData)

	_, err = r.exec(ctx, `
		INSERT INTO scan_results (
			id, node_id, hostname, started_at, finished_at, trigger, runner_name,
			target_type, target_id, target_host, target_port, target_db,
			run_status, features_run, overall_score, total_pass, total_fail, report_json,
			error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, meta.NodeID, meta.Hostname,
		started.UTC().Format(time.RFC3339), finished.UTC().Format(time.RFC3339),
		trigger, meta.RunnerName,
		"postgres", tid, host, port, dbName,
		status, string(featuresJSON), score, pass, fail, string(blob),
		meta.ErrorMessage)
	if err != nil {
		return "", fmt.Errorf("insert scan_result: %w", err)
	}
	return id, nil
}

func (r *Repository) PersistPIIReport(ctx context.Context, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error {
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
	tid := reportstore.TargetID(pg)
	now := time.Now().UTC().Format(time.RFC3339)

	var existingID, existingFeatures sql.NullString
	err = r.queryRow(ctx, `
		SELECT id, features_run FROM scan_results
		WHERE target_id = ?
		ORDER BY started_at DESC LIMIT 1
	`, tid).Scan(&existingID, &existingFeatures)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup run: %w", err)
	}
	if existingID.Valid && existingID.String != "" {
		features := mergeFeaturesRun(existingFeatures.String, cons.RootCMD_PiiScanner)
		_, err := r.exec(ctx, `
			UPDATE scan_results SET pii_report_json = ?, pii_scanned_at = ?, features_run = ?
			WHERE id = ?
		`, string(blob), now, features, existingID.String)
		return err
	}
	return r.insertPIIOnlyRun(ctx, pg, tid, blob, now)
}

func (r *Repository) insertPIIOnlyRun(ctx context.Context, pg *postgresdb.Postgres, tid string, piiBlob []byte, scannedAt string) error {
	id := uuid.NewString()
	now := time.Now().UTC()
	started := now.Format(time.RFC3339)
	host, port, dbName := targetFields(pg)
	featuresJSON, _ := json.Marshal([]string{cons.RootCMD_PiiScanner})
	emptyReport := `{}`
	_, err := r.exec(ctx, `
		INSERT INTO scan_results (
			id, node_id, hostname, started_at, finished_at, trigger, runner_name,
			target_type, target_id, target_host, target_port, target_db,
			run_status, features_run, overall_score, total_pass, total_fail, report_json,
			pii_report_json, pii_scanned_at, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, "pii-scan", host, started, started, "manual", "ciscollector",
		"postgres", tid, host, port, dbName,
		"success", string(featuresJSON), 0, 0, 0, emptyReport,
		string(piiBlob), scannedAt, "")
	return err
}

func (r *Repository) PersistBackupComplianceReport(ctx context.Context, meta reportstore.BackupComplianceReportMeta, reportJSON map[string]interface{}) error {
	return reportstore.PersistBackupComplianceReport(ctx, r.db, meta, reportJSON)
}

func (r *Repository) GetLatestRun(ctx context.Context, targetID string) (*reportstore.RunRow, error) {
	q := `SELECT ` + runSelectColumns + ` FROM ` + runsTable
	args := []interface{}{}
	if targetID != "" {
		q += ` WHERE target_id = ?`
		args = append(args, targetID)
	}
	q += ` ORDER BY started_at DESC,
		CASE WHEN report_json IS NOT NULL AND length(trim(report_json::text)) > 2 THEN 0 ELSE 1 END,
		finished_at DESC LIMIT 1`
	return scanRunRow(r.queryRow(ctx, q, args...))
}

func (r *Repository) GetLatestRunWithPII(ctx context.Context, targetID string) (*reportstore.RunRow, error) {
	if targetID == "" {
		return nil, nil
	}
	return scanRunRow(r.queryRow(ctx, `
		SELECT `+runSelectColumns+`
		FROM scan_results
		WHERE target_id = ?
		  AND pii_report_json IS NOT NULL
		  AND length(trim(pii_report_json::text)) > 2
		ORDER BY COALESCE(NULLIF(pii_scanned_at, ''), started_at) DESC
		LIMIT 1
	`, targetID))
}

func (r *Repository) ListLatestBackupComplianceReports(ctx context.Context) ([]reportstore.BackupComplianceRow, error) {
	return reportstore.ListLatestBackupComplianceReports(ctx, r.db)
}

func (r *Repository) GetLatestRunWithBackupCompliance(ctx context.Context, targetID string) (*reportstore.BackupComplianceRow, error) {
	return reportstore.GetLatestRunWithBackupCompliance(ctx, r.db, targetID)
}

func (r *Repository) GetRunByID(ctx context.Context, id string) (*reportstore.RunRow, error) {
	return scanRunRow(r.queryRow(ctx, `
		SELECT `+runSelectColumns+`
		FROM scan_results WHERE id = ?
	`, id))
}

func (r *Repository) GetRuns(ctx context.Context, limit int) ([]reportstore.RunRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.query(ctx, `
		SELECT `+runSelectColumns+`
		FROM scan_results ORDER BY started_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRunsFromRows(rows)
}

func (r *Repository) ListRunTargetIDs(ctx context.Context) ([]string, error) {
	rows, err := r.query(ctx, `
		SELECT target_id FROM scan_results
		WHERE target_id IS NOT NULL AND trim(target_id) != ''
		GROUP BY target_id
		ORDER BY max(started_at) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var tid string
		if err := rows.Scan(&tid); err != nil {
			return nil, err
		}
		if strings.TrimSpace(tid) != "" {
			out = append(out, tid)
		}
	}
	return out, rows.Err()
}

func (r *Repository) GetRunsForTarget(ctx context.Context, targetID string, limit int) ([]reportstore.RunRow, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 15
	}
	rows, err := r.query(ctx, `
		SELECT `+runSelectColumns+`
		FROM scan_results WHERE target_id = ?
		ORDER BY started_at DESC LIMIT ?
	`, targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRunsFromRows(rows)
}

func (r *Repository) UpsertGucBaseline(ctx context.Context, label string, settings map[string]string) error {
	if settings == nil {
		settings = map[string]string{}
	}
	if label == "" {
		label = "global"
	}
	blob, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = r.exec(ctx, `
		INSERT INTO guc_baseline (id, label, settings_json, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			label = excluded.label,
			settings_json = excluded.settings_json,
			updated_at = excluded.updated_at
	`, gucBaselineRowID, label, string(blob), now)
	return err
}

func (r *Repository) GetGucBaseline(ctx context.Context) (string, map[string]string, string, error) {
	var label, blob, updatedAt string
	err := r.queryRow(ctx, `
		SELECT label, settings_json, updated_at FROM guc_baseline WHERE id = ?
	`, gucBaselineRowID).Scan(&label, &blob, &updatedAt)
	if err == sql.ErrNoRows {
		return "", map[string]string{}, "", nil
	}
	if err != nil {
		return "", nil, "", err
	}
	settings := map[string]string{}
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &settings); err != nil {
			return "", nil, "", fmt.Errorf("decode baseline: %w", err)
		}
	}
	return label, settings, updatedAt, nil
}

func (r *Repository) UpsertServerGucSnapshot(ctx context.Context, targetID, targetHost, nodeID string, settings map[string]string) error {
	if targetID == "" {
		return fmt.Errorf("target_id is required")
	}
	if settings == nil {
		settings = map[string]string{}
	}
	blob, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if nodeID == "" {
		nodeID = uuid.NewString()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = r.exec(ctx, `
		INSERT INTO server_guc_snapshots (target_id, target_host, node_id, settings_json, collected_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(target_id) DO UPDATE SET
			target_host = excluded.target_host,
			node_id = excluded.node_id,
			settings_json = excluded.settings_json,
			collected_at = excluded.collected_at
	`, targetID, targetHost, nodeID, string(blob), now)
	return err
}

func (r *Repository) GetServerGucSnapshot(ctx context.Context, targetID string) (map[string]string, string, string, error) {
	var blob, host, collectedAt string
	err := r.queryRow(ctx, `
		SELECT target_host, settings_json, collected_at
		FROM server_guc_snapshots WHERE target_id = ?
	`, targetID).Scan(&host, &blob, &collectedAt)
	if err == sql.ErrNoRows {
		return nil, "", "", nil
	}
	if err != nil {
		return nil, "", "", err
	}
	settings := map[string]string{}
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &settings); err != nil {
			return nil, "", "", fmt.Errorf("decode snapshot: %w", err)
		}
	}
	return settings, host, collectedAt, nil
}

func (r *Repository) ListServerGucSnapshots(ctx context.Context) ([]reportstore.GucSnapshotSummary, error) {
	rows, err := r.query(ctx, `
		SELECT target_id, target_host, node_id, collected_at, settings_json
		FROM server_guc_snapshots
		ORDER BY target_host ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reportstore.GucSnapshotSummary
	for rows.Next() {
		var s reportstore.GucSnapshotSummary
		var blob string
		if err := rows.Scan(&s.TargetID, &s.TargetHost, &s.NodeID, &s.CollectedAt, &blob); err != nil {
			return nil, err
		}
		settings := map[string]string{}
		if blob != "" {
			_ = json.Unmarshal([]byte(blob), &settings)
		}
		s.KeyCount = len(settings)
		for k := range settings {
			if strings.HasPrefix(k, "__kshield_") {
				s.KeyCount--
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repository) UpsertGucIgnore(ctx context.Context, scope, targetID, gucName string) error {
	scope = strings.TrimSpace(strings.ToLower(scope))
	targetID = strings.TrimSpace(targetID)
	gucName = strings.ToLower(strings.TrimSpace(gucName))
	if scope != reportstore.GucIgnoreScopeHost && scope != reportstore.GucIgnoreScopeGuc {
		return fmt.Errorf("scope must be host or guc")
	}
	if targetID == "" {
		return fmt.Errorf("target_id is required")
	}
	if scope == reportstore.GucIgnoreScopeGuc && gucName == "" {
		return fmt.Errorf("guc is required for guc-scope ignore")
	}
	if scope == reportstore.GucIgnoreScopeHost {
		gucName = ""
	}
	instanceKey := reportstore.GucInstanceKey(targetID)
	if instanceKey == "" {
		instanceKey = targetID
	}
	id := scope + "|" + instanceKey
	if scope == reportstore.GucIgnoreScopeGuc {
		id += "|" + gucName
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.exec(ctx, `
		INSERT INTO guc_drift_ignores (id, scope, target_id, instance_key, guc_name, ignored_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			target_id = excluded.target_id,
			ignored_at = excluded.ignored_at
	`, id, scope, targetID, instanceKey, gucName, now)
	return err
}

func (r *Repository) DeleteGucIgnore(ctx context.Context, scope, targetID, gucName string) error {
	scope = strings.TrimSpace(strings.ToLower(scope))
	targetID = strings.TrimSpace(targetID)
	gucName = strings.ToLower(strings.TrimSpace(gucName))
	if scope == reportstore.GucIgnoreScopeHost {
		gucName = ""
	}
	instanceKey := reportstore.GucInstanceKey(targetID)
	if instanceKey == "" {
		instanceKey = targetID
	}
	id := scope + "|" + instanceKey
	if scope == reportstore.GucIgnoreScopeGuc {
		id += "|" + gucName
	}
	_, err := r.exec(ctx, `DELETE FROM guc_drift_ignores WHERE id = ?`, id)
	return err
}

func (r *Repository) ListGucIgnores(ctx context.Context) ([]reportstore.GucIgnoreEntry, error) {
	rows, err := r.query(ctx, `
		SELECT id, scope, target_id, instance_key, guc_name, ignored_at
		FROM guc_drift_ignores
		ORDER BY ignored_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reportstore.GucIgnoreEntry
	for rows.Next() {
		var e reportstore.GucIgnoreEntry
		if err := rows.Scan(&e.ID, &e.Scope, &e.TargetID, &e.InstanceKey, &e.GucName, &e.IgnoredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *Repository) UpsertGucServerGroup(ctx context.Context, id, name, description string, baseline map[string]string) (string, error) {
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
	_, err = r.exec(ctx, `
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

func (r *Repository) DeleteGucServerGroup(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if _, err := r.exec(ctx, `DELETE FROM guc_server_group_members WHERE group_id = ?`, id); err != nil {
		return err
	}
	_, err := r.exec(ctx, `DELETE FROM guc_server_groups WHERE id = ?`, id)
	return err
}

func (r *Repository) GetGucServerGroup(ctx context.Context, id string) (*reportstore.GucServerGroup, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, nil
	}
	var g reportstore.GucServerGroup
	var blob string
	err := r.queryRow(ctx, `
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
	members, err := r.listGucServerGroupMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	g.MemberIDs = members
	return &g, nil
}

func (r *Repository) ListGucServerGroups(ctx context.Context) ([]reportstore.GucServerGroup, error) {
	rows, err := r.query(ctx, `
		SELECT id, name, description, baseline_json, updated_at
		FROM guc_server_groups
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reportstore.GucServerGroup
	for rows.Next() {
		var g reportstore.GucServerGroup
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
		members, err := r.listGucServerGroupMembers(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].MemberIDs = members
	}
	return out, nil
}

func (r *Repository) listGucServerGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	rows, err := r.query(ctx, `
		SELECT target_id FROM guc_server_group_members
		WHERE group_id = ?
		ORDER BY target_id ASC
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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

func (r *Repository) SetGucServerGroupMembers(ctx context.Context, groupID string, targetIDs []string) error {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return fmt.Errorf("group_id is required")
	}
	if _, err := r.exec(ctx, `DELETE FROM guc_server_group_members WHERE group_id = ?`, groupID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, tid := range targetIDs {
		tid = strings.TrimSpace(tid)
		if tid == "" || seen[tid] {
			continue
		}
		seen[tid] = true
		if _, err := r.exec(ctx, `
			INSERT INTO guc_server_group_members (group_id, target_id) VALUES (?, ?)
		`, groupID, tid); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) SetGucServerGroupBaseline(ctx context.Context, groupID string, baseline map[string]string) error {
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
	res, err := r.exec(ctx, `
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

func (r *Repository) UpsertBackupCompliancePolicy(ctx context.Context, policy reportstore.BackupCompliancePolicyStored) error {
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
	_, err = r.exec(ctx, `
		INSERT INTO backup_compliance_policy (id, policy_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			policy_json = excluded.policy_json,
			updated_at = excluded.updated_at
	`, "global", string(blob), now)
	return err
}

func (r *Repository) GetBackupCompliancePolicy(ctx context.Context) (reportstore.BackupCompliancePolicyStored, string, error) {
	var blob, updatedAt string
	err := r.queryRow(ctx, `
		SELECT policy_json, updated_at FROM backup_compliance_policy WHERE id = ?
	`, "global").Scan(&blob, &updatedAt)
	if err == sql.ErrNoRows {
		return reportstore.BackupCompliancePolicyStored{AllowedDays: []string{}}, "", nil
	}
	if err != nil {
		return reportstore.BackupCompliancePolicyStored{}, "", err
	}
	var policy reportstore.BackupCompliancePolicyStored
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &policy); err != nil {
			return reportstore.BackupCompliancePolicyStored{}, "", fmt.Errorf("decode backup compliance policy: %w", err)
		}
	}
	if policy.AllowedDays == nil {
		policy.AllowedDays = []string{}
	}
	return policy, updatedAt, nil
}

func (r *Repository) UpsertCollectorStatus(ctx context.Context, nodeID, hostname, ip string, ts time.Time, cronRunning bool, scheduledJobs int, lastError string) error {
	cronVal := 0
	if cronRunning {
		cronVal = 1
	}
	_, err := r.exec(ctx, `
		INSERT INTO collector_status (
			node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_error, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			hostname = excluded.hostname,
			ip = excluded.ip,
			last_seen_at = excluded.last_seen_at,
			cron_running = excluded.cron_running,
			scheduled_jobs = excluded.scheduled_jobs,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at
	`, nodeID, hostname, strings.TrimSpace(ip), ts, cronVal, scheduledJobs,
		strings.TrimSpace(lastError), time.Now().UTC())
	return err
}

func (r *Repository) InsertCollectorActivity(ctx context.Context, nodeID, kind, message, level string, ts time.Time) error {
	_, err := r.exec(ctx, `
		INSERT INTO collector_activity (node_id, kind, message, level, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(kind), message, strings.TrimSpace(level), ts)
	return err
}

func (r *Repository) TouchCollectorLastSeen(ctx context.Context, nodeID string, ts time.Time) error {
	_, err := r.exec(ctx, `
		UPDATE collector_status SET last_seen_at = ?, updated_at = ? WHERE node_id = ?
	`, ts, time.Now().UTC(), nodeID)
	return err
}

func (r *Repository) InsertCollectorLog(ctx context.Context, nodeID, level, message string, ts time.Time) error {
	_, err := r.exec(ctx, `
		INSERT INTO collector_logs (node_id, level, message, created_at)
		VALUES (?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(level), message, ts)
	return err
}

func (r *Repository) InsertCollectorRun(ctx context.Context, nodeID, hostname, trigger string, startedAt, finishedAt time.Time, features []string, success bool, errMsg string) error {
	featuresJSON, _ := json.Marshal(features)
	successVal := 0
	if success {
		successVal = 1
	}
	if _, err := r.exec(ctx, `
		INSERT INTO collector_runs (node_id, trigger, started_at, finished_at, features, success, error)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, nodeID, strings.TrimSpace(trigger), startedAt, finishedAt, string(featuresJSON), successVal, strings.TrimSpace(errMsg)); err != nil {
		return err
	}
	_, err := r.exec(ctx, `
		INSERT INTO collector_status (node_id, hostname, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error, updated_at)
		VALUES (?, ?, ?, 0, 0, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			hostname = COALESCE(excluded.hostname, collector_status.hostname),
			last_seen_at = excluded.last_seen_at,
			last_run_at = excluded.last_run_at,
			last_error = CASE WHEN excluded.last_error != '' THEN excluded.last_error ELSE collector_status.last_error END,
			updated_at = excluded.updated_at
	`, nodeID, hostname, finishedAt, finishedAt, strings.TrimSpace(errMsg), time.Now().UTC())
	return err
}

func (r *Repository) ListCollectorNodes(ctx context.Context) ([]reprows.CollectorNodeRow, error) {
	rows, err := r.query(ctx, `
		SELECT node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error
		FROM collector_status ORDER BY hostname ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCollectorNodes(rows)
}

func (r *Repository) GetCollectorNode(ctx context.Context, nodeID string) (*reprows.CollectorNodeRow, error) {
	n, err := scanCollectorNodeRow(r.queryRow(ctx, `
		SELECT node_id, hostname, ip, last_seen_at, cron_running, scheduled_jobs, last_run_at, last_error
		FROM collector_status WHERE node_id = ?
	`, nodeID))
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, sql.ErrNoRows
	}
	return n, nil
}

func (r *Repository) ListCollectorRuns(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorRunRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.query(ctx, `
		SELECT id, trigger, started_at, finished_at, features, success, error
		FROM collector_runs WHERE node_id = ? ORDER BY started_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCollectorRuns(rows)
}

func (r *Repository) ListCollectorActivity(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorActivityRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.query(ctx, `
		SELECT kind, message, level, created_at FROM collector_activity
		WHERE node_id = ? ORDER BY created_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reprows.CollectorActivityRow
	for rows.Next() {
		var a reprows.CollectorActivityRow
		if err := rows.Scan(&a.Kind, &a.Message, &a.Level, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *Repository) ListCollectorLogs(ctx context.Context, nodeID string, limit int) ([]reprows.CollectorLogRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.query(ctx, `
		SELECT level, message, created_at FROM collector_logs
		WHERE node_id = ? ORDER BY created_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reprows.CollectorLogRow
	for rows.Next() {
		var row reprows.CollectorLogRow
		var level sql.NullString
		if err := rows.Scan(&level, &row.Message, &row.CreatedAt); err != nil {
			return nil, err
		}
		if level.Valid {
			row.Level = level.String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
