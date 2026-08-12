package postgres

func schemaStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS scan_results (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			hostname TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			trigger TEXT NOT NULL DEFAULT 'cron',
			runner_name TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL DEFAULT 'postgres',
			target_id TEXT NOT NULL,
			target_host TEXT NOT NULL,
			target_port TEXT NOT NULL DEFAULT '',
			target_db TEXT NOT NULL DEFAULT '',
			run_status TEXT NOT NULL,
			features_run TEXT,
			overall_score DOUBLE PRECISION,
			total_pass INTEGER DEFAULT 0,
			total_fail INTEGER DEFAULT 0,
			report_json JSONB NOT NULL,
			pii_report_json JSONB,
			pii_scanned_at TEXT,
			backup_compliance_json JSONB,
			backup_compliance_scanned_at TEXT,
			error_message TEXT
		)`,
		`ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS backup_compliance_json JSONB`,
		`ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS backup_compliance_scanned_at TEXT`,
		`CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_results_node ON scan_results(node_id, started_at DESC)`,
		`CREATE TABLE IF NOT EXISTS guc_baseline (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL DEFAULT 'global',
			settings_json JSONB NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS server_guc_snapshots (
			target_id TEXT PRIMARY KEY,
			target_host TEXT NOT NULL,
			node_id TEXT NOT NULL,
			settings_json JSONB NOT NULL,
			collected_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS guc_drift_ignores (
			id TEXT PRIMARY KEY,
			scope TEXT NOT NULL,
			target_id TEXT NOT NULL,
			instance_key TEXT NOT NULL,
			guc_name TEXT NOT NULL DEFAULT '',
			ignored_at TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_guc_drift_ignores_unique
			ON guc_drift_ignores(scope, instance_key, guc_name)`,
		`CREATE TABLE IF NOT EXISTS guc_server_groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			baseline_json JSONB NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS guc_server_group_members (
			group_id TEXT NOT NULL,
			target_id TEXT NOT NULL,
			PRIMARY KEY (group_id, target_id)
		)`,
		`CREATE TABLE IF NOT EXISTS backup_compliance_policy (
			id TEXT PRIMARY KEY,
			policy_json JSONB NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS collector_status (
			node_id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			ip TEXT,
			last_seen_at TIMESTAMPTZ NOT NULL,
			cron_running INTEGER NOT NULL DEFAULT 0,
			scheduled_jobs INTEGER NOT NULL DEFAULT 0,
			last_run_at TIMESTAMPTZ,
			last_error TEXT,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS collector_runs (
			id BIGSERIAL PRIMARY KEY,
			node_id TEXT NOT NULL,
			trigger TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			finished_at TIMESTAMPTZ,
			features TEXT,
			success INTEGER NOT NULL DEFAULT 0,
			error TEXT,
			FOREIGN KEY(node_id) REFERENCES collector_status(node_id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_collector_runs_node_started ON collector_runs(node_id, started_at DESC)`,
		`CREATE TABLE IF NOT EXISTS collector_activity (
			id BIGSERIAL PRIMARY KEY,
			node_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			message TEXT NOT NULL,
			level TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(node_id) REFERENCES collector_status(node_id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_collector_activity_node_created ON collector_activity(node_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS collector_logs (
			id BIGSERIAL PRIMARY KEY,
			node_id TEXT NOT NULL,
			level TEXT,
			message TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(node_id) REFERENCES collector_status(node_id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_collector_logs_node_created ON collector_logs(node_id, created_at DESC)`,
	}
}
