package service

import "time"

// HostsResponse is the grouped PostgreSQL instance list for the Hosts page.
type HostsResponse struct {
	Instances []HostInstance `json:"instances"`
	Rows      [][]string     `json:"rows,omitempty"`
}

// HostInstance is one PostgreSQL server (host:port) with one or more databases.
type HostInstance struct {
	Instance       string              `json:"instance"`
	IP             string              `json:"ip"`
	DatabaseCount  int                 `json:"database_count"`
	Databases      []HostDatabaseBrief `json:"databases"`
	FailingCount   int                 `json:"failing_count"`
	Posture        string              `json:"posture"`
	DatabasesLabel string              `json:"databases_label"`
	FailLabel      string              `json:"fail_label"`
	PostureLabel   string              `json:"posture_label"`
	Agent          string              `json:"agent"`
	LastAudit      string              `json:"last_audit"`
}

// HostDatabaseBrief summarizes one database on an instance.
type HostDatabaseBrief struct {
	Name      string `json:"name"`
	HostKey   string `json:"host_key"`
	CisPct    string `json:"cis_pct"`
	Posture   string `json:"posture"`
	LastAudit string `json:"last_audit"`
}

// HostInstanceResponse lists databases on one instance for the host overview selector.
type HostInstanceResponse struct {
	Instance  string              `json:"instance"`
	IP        string              `json:"ip"`
	Databases []HostDatabaseBrief `json:"databases"`
	DefaultDB string              `json:"default_database"`
}

// ViolationsResponse matches front/mock-data/violations.json.
type ViolationsResponse struct {
	Critical        []ViolationEntry       `json:"critical"`
	High            []ViolationEntry       `json:"high"`
	Medium          []ViolationEntry       `json:"medium"`
	Rows            []CriticalViolationRow `json:"rows,omitempty"`
	TypeOptions     []string               `json:"type_options,omitempty"`
	SeverityOptions []string               `json:"severity_options,omitempty"`
}

type ViolationEntry struct {
	Host          string `json:"host"`
	Check         string `json:"check"`
	Severity      string `json:"severity"`
	ViolationType string `json:"violation_type,omitempty"`
	DetectedAt    string `json:"detected_at,omitempty"`
}

// CriticalViolationRow is the expanded shape for prototype-app CRITICAL_VIOLATIONS.
type CriticalViolationRow struct {
	ID            string `json:"id"`
	Server        string `json:"server"`
	Type          string `json:"type"`
	Details       string `json:"details"`
	Severity      string `json:"severity"`
	Detected      string `json:"detected"`
	Status        string `json:"status"`
	ConfigSection string `json:"configSection"`
}

// CriticalChecksResponse is the fleet-wide critical violations payload.
type CriticalChecksResponse struct {
	Checks          []CriticalCheckDef     `json:"checks"`
	HostRows        []CriticalCheckHostRow `json:"host_rows"`
	CheckFails      []int                  `json:"check_fails,omitempty"`
	Rows            []CriticalCheckRow     `json:"rows,omitempty"`
	CheckOptions    []string               `json:"check_options,omitempty"`
	ServerOptions   []string               `json:"server_options,omitempty"`
	SourceOptions   []string               `json:"source_options,omitempty"`
	TypeOptions     []string               `json:"type_options,omitempty"`
	SeverityOptions []string               `json:"severity_options,omitempty"`
}

type CriticalCheckDef struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

type CriticalCheckHostRow struct {
	Host     string                `json:"host"`
	Detected string                `json:"detected_at"`
	Failed   int                   `json:"failed"`
	Checks   []CriticalCheckResult `json:"checks"`
}

type CriticalCheckResult struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
	Source  string `json:"source,omitempty"`
}

// CriticalCheckRow is a flattened failing violation for the drill-down table.
type CriticalCheckRow struct {
	ID            string `json:"id"`
	CheckID       int    `json:"check_id"`
	Check         string `json:"check"`
	Server        string `json:"server"`
	Details       string `json:"details"`
	Status        string `json:"status"`
	Detected      string `json:"detected"`
	Source        string `json:"source,omitempty"`
	ViolationType string `json:"violation_type,omitempty"`
	Severity      string `json:"severity,omitempty"`
}

// StrategicResponse matches front/mock-data/strategic-30d.json (+ widget fields).
type StrategicResponse struct {
	Ranges map[string]StrategicRange `json:"ranges"`
}

type StrategicRange struct {
	Label          string           `json:"label"`
	Health         int              `json:"health"`
	Grade          string           `json:"grade"`
	GradeColor     string           `json:"gradeColor"`
	Critical       int              `json:"critical"`
	CIS            int              `json:"cis"`
	Servers        int              `json:"servers"`
	OnPrem         int              `json:"onPrem"`
	Cloud          int              `json:"cloud"`
	Privs          []StrategicBar   `json:"privs,omitempty"`
	Hygiene        StrategicHygiene `json:"hygiene,omitempty"`
	Cred           StrategicCred    `json:"cred,omitempty"`
	HBA            []StrategicHBA   `json:"hba,omitempty"`
	HBAScanned     bool             `json:"hbaScanned,omitempty"`
	SSLEnforced    int              `json:"sslEnforced,omitempty"`
	SSLScanned     bool             `json:"sslScanned,omitempty"`
	RDSPublic      int              `json:"rdsPublic,omitempty"`
	AuroraUnenc    int              `json:"auroraUnenc,omitempty"`
	CloudScanned   bool             `json:"cloudScanned,omitempty"`
	PlatformSource string           `json:"platformSource,omitempty"` // "cloud" | "postgres"
	Drift          []StrategicDrift `json:"drift,omitempty"`
	DriftLabels    []string         `json:"driftLabels,omitempty"`
	Audit          [][]string       `json:"audit,omitempty"`
	Heatmap        [][]int          `json:"heatmap,omitempty"`
	HeatmapColumns []string         `json:"heatmapColumns,omitempty"`
	PiiScanned     bool             `json:"piiScanned,omitempty"`
}

type StrategicBar struct {
	L string `json:"l"`
	A int    `json:"a"`
	U int    `json:"u"`
}

type StrategicHygiene struct {
	Active   int `json:"active"`
	Inactive int `json:"inactive"`
	Common   int `json:"common"`
}

type StrategicCred struct {
	Hosts   int `json:"hosts"`
	Exposed int `json:"exposed"`
	Weak    int `json:"weak"`
	Ok      int `json:"ok"`
}

type StrategicHBA struct {
	L string `json:"l"`
	O int    `json:"o"`
	I int    `json:"i"`
	S int    `json:"s"`
}

type StrategicDrift struct {
	B int `json:"b"`
	D int `json:"d"`
}

// FleetCategoriesResponse matches front/mock-data/fleet-categories.json.
type FleetCategoriesResponse struct {
	Categories []FleetCategory `json:"categories"`
}

type FleetCategory struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Level     string     `json:"level"`
	Count     string     `json:"count"`
	Menu      string     `json:"menu"`
	Cols      []string   `json:"cols"`
	Rows      [][]string `json:"rows"`
	UserTable bool       `json:"userTable,omitempty"`
}

// RunsResponse lists scan history.
type RunsResponse struct {
	Runs []RunSummary `json:"runs"`
}

type RunSummary struct {
	ID           string    `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	DurationMs   int64     `json:"duration_ms"`
	Trigger      string    `json:"trigger"`
	TargetID     string    `json:"target_id"`
	TargetHost   string    `json:"target_host"`
	OverallScore float64   `json:"overall_score"`
	TotalPass    int       `json:"total_pass"`
	TotalFail    int       `json:"total_fail"`
}

// OverviewResponse is the legacy main-server overview shape (servers from reportstore).
type OverviewResponse struct {
	Summary       OverviewSummary  `json:"summary"`
	CentralServer OverviewServer   `json:"central_server"`
	Servers       []OverviewServer `json:"servers"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type OverviewSummary struct {
	Servers  int `json:"servers"`
	Healthy  int `json:"healthy"`
	Warning  int `json:"warning"`
	Critical int `json:"critical"`
}

type OverviewServer struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	ServerSummary struct {
		TotalCases  int `json:"total_cases"`
		PassedCases int `json:"passed_cases"`
	} `json:"server_summary"`
}

// HostReportResponse is the structured host detail payload for /api/servers/{id}.
type HostReportResponse struct {
	Host           HostSummary           `json:"host"`
	Modules        HostReportModules     `json:"modules"`
	GucDriftDetail HostGucDriftView      `json:"guc_drift_detail"`
	CriticalChecks []CriticalCheckResult `json:"critical_checks,omitempty"`
	CriticalFailed int                   `json:"critical_failed,omitempty"`
	RawKeys        []string              `json:"raw_keys"`

	HtmlExport *HtmlExportMeta `json:"html_export,omitempty"`

	// Legacy top-level fields (backward compatible with earlier clients).
	ID                   string        `json:"id,omitempty"`
	Name                 string        `json:"name,omitempty"`
	IP                   string        `json:"ip,omitempty"`
	Status               string        `json:"status,omitempty"`
	PostgresCISResponses []interface{} `json:"postgres_cis_responses,omitempty"`
	HBAScanResult        []interface{} `json:"hba_scan_result,omitempty"`
	SSLScanResult        interface{}   `json:"ssl_scan_result,omitempty"`
	UserListResult       interface{}   `json:"user_list_result,omitempty"`
}

type HostSummary struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	IP             string `json:"ip"`
	Status         string `json:"status"`
	CisPct         string `json:"cis_pct"`
	FailedControls int    `json:"failed_controls"`
	GucDrift       string `json:"guc_drift"`
	Agent          string `json:"agent"`
	LastAudit      string `json:"last_audit"`
	PostgresVer    string `json:"postgres_version,omitempty"`
}

type HtmlExportMeta struct {
	Available   bool   `json:"available"`
	RunID       string `json:"run_id,omitempty"`
	OpenURL     string `json:"open_url,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

type HostReportModules struct {
	CisAudit           HostModuleView `json:"cis_audit"`
	ConfigAudit        HostModuleView `json:"config_audit"`
	LoggingGucs        HostModuleView `json:"logging_gucs"`
	WalReplication     HostModuleView `json:"wal_replication"`
	BackupMonitoring   HostModuleView `json:"backup_monitoring"`
	XidMonitoring      HostModuleView `json:"xid_monitoring"`
	RolesPrivileges    HostModuleView `json:"roles_privileges"`
	PgHba              HostModuleView `json:"pg_hba"`
	SslTls             HostModuleView `json:"ssl_tls"`
	PasswordAudit      HostModuleView `json:"password_audit"`
	ConnectionSecurity HostModuleView `json:"connection_security"`
	PiiResults         HostModuleView `json:"pii_results"`
	LogParser          HostModuleView `json:"log_parser"`
}

type HostModuleView struct {
	Available   bool               `json:"available"`
	EmptyReason string             `json:"empty_reason,omitempty"`
	Columns     []string           `json:"columns,omitempty"`
	Rows        []HostTableRow     `json:"rows,omitempty"`
	Sections    []HostSectionScore `json:"sections,omitempty"`
	Summary     []HostKV           `json:"summary,omitempty"`
	Callout     string             `json:"callout,omitempty"`
}

type HostTableRow struct {
	Cells  []string `json:"cells"`
	Status string   `json:"status,omitempty"`
}

type HostSectionScore struct {
	Label string `json:"label"`
	Pct   int    `json:"pct"`
}

type HostKV struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Status string `json:"status,omitempty"`
}

// GucDriftResponse fleet GUC drift vs global (or group) baseline.
type GucDriftResponse struct {
	Stats         GucDriftStats         `json:"stats"`
	HostSummaries []GucDriftHostSummary `json:"host_summaries"`
	Rows          []GucDriftRow         `json:"rows"`
	GroupID       string                `json:"group_id,omitempty"`
	GroupName     string                `json:"group_name,omitempty"`
}

type GucDriftStats struct {
	BaselineLabel       string `json:"baseline_label"`
	BaselineKeys        int    `json:"baseline_keys"`
	BaselineSource      string `json:"baseline_source,omitempty"` // host | file | none
	BaselineTargetID    string `json:"baseline_target_id,omitempty"`
	BaselineHost        string `json:"baseline_host,omitempty"`
	BaselineMajor       int    `json:"baseline_major,omitempty"`
	HostsCompared       int    `json:"hosts_compared"`
	MatchedServers      int    `json:"matched_servers"`
	DriftingServers     int    `json:"drifting_servers"`
	MissingServers      int    `json:"missing_servers"`
	IgnoredServers      int    `json:"ignored_servers"`
	TotalDrifted        int    `json:"total_drifted"`
	TotalMissing        int    `json:"total_missing"`
	TotalIgnored        int    `json:"total_ignored"`
	TotalVersionUpdated int    `json:"total_version_updated,omitempty"`
	TotalVersionNew     int    `json:"total_version_new,omitempty"`
	TotalVersionRemoved int    `json:"total_version_removed,omitempty"`
}

type GucDriftHostSummary struct {
	Host                string `json:"host"`
	TargetID            string `json:"target_id"`
	Status              string `json:"status"`
	DriftCount          int    `json:"drift_count"`
	MissingCount        int    `json:"missing_count"`
	IgnoredCount        int    `json:"ignored_count"`
	VersionUpdatedCount int    `json:"version_updated_count,omitempty"`
	VersionNewCount     int    `json:"version_new_count,omitempty"`
	VersionRemovedCount int    `json:"version_removed_count,omitempty"`
	PostgresMajor       int    `json:"postgres_major,omitempty"`
	HostIgnored         bool   `json:"host_ignored,omitempty"`
}

type GucDriftRow struct {
	Host     string `json:"host"`
	TargetID string `json:"target_id"`
	Guc      string `json:"guc"`
	Live     string `json:"live"`
	Baseline string `json:"baseline"`
	Status   string `json:"status"`
	Ignored  bool   `json:"ignored,omitempty"`
}

// HostGucDriftView is per-host GUC drift vs the global baseline.
type HostGucDriftView struct {
	Available           bool          `json:"available"`
	Status              string        `json:"status"`
	BaselineLabel       string        `json:"baseline_label,omitempty"`
	BaselineMajor       int           `json:"baseline_major,omitempty"`
	PostgresMajor       int           `json:"postgres_major,omitempty"`
	DriftCount          int           `json:"drift_count"`
	MissingCount        int           `json:"missing_count"`
	IgnoredCount        int           `json:"ignored_count,omitempty"`
	VersionUpdatedCount int           `json:"version_updated_count,omitempty"`
	VersionNewCount     int           `json:"version_new_count,omitempty"`
	VersionRemovedCount int           `json:"version_removed_count,omitempty"`
	Rows                []GucDriftRow `json:"rows,omitempty"`
	EmptyReason         string        `json:"empty_reason,omitempty"`
	HostIgnored         bool          `json:"host_ignored,omitempty"`
}

type GucBaselineResponse struct {
	Label     string            `json:"label"`
	Source    string            `json:"source"` // host | file | none
	TargetID  string            `json:"target_id,omitempty"`
	Host      string            `json:"host,omitempty"`
	Settings  map[string]string `json:"settings"`
	UpdatedAt string            `json:"updated_at"`
	KeyCount  int               `json:"key_count"`
	GroupID   string            `json:"group_id,omitempty"`
}

type GucSnapshotsResponse struct {
	Snapshots []GucSnapshotEntry `json:"snapshots"`
}

type GucSnapshotEntry struct {
	TargetID    string `json:"target_id"`
	Host        string `json:"host"`
	NodeID      string `json:"node_id"`
	CollectedAt string `json:"collected_at"`
	KeyCount    int    `json:"key_count"`
}

type GucIgnoreEntryDTO struct {
	Scope       string `json:"scope"`
	TargetID    string `json:"target_id"`
	InstanceKey string `json:"instance_key"`
	Guc         string `json:"guc,omitempty"`
	IgnoredAt   string `json:"ignored_at"`
}

type GucIgnoresResponse struct {
	Ignores []GucIgnoreEntryDTO `json:"ignores"`
}

type GucServerGroupDTO struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	MemberIDs   []string             `json:"member_ids"`
	MemberCount int                  `json:"member_count"`
	Baseline    *GucBaselineResponse `json:"baseline,omitempty"`
	UpdatedAt   string               `json:"updated_at"`
}

type GucServerGroupsResponse struct {
	Groups []GucServerGroupDTO `json:"groups"`
}

// PoliciesResponse security policy templates and assignments.
type PoliciesResponse struct {
	Checks      []PolicyCheck      `json:"checks"`
	Templates   []PolicyTemplate   `json:"templates"`
	Groups      []PolicyGroup      `json:"groups"`
	HostMap     []PolicyHostMap    `json:"host_map"`
	Definitions []PolicyDefinition `json:"definitions"`
}

type PolicyCheck struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Cmd   string `json:"cmd"`
	Menu  string `json:"menu"`
}

type PolicyTemplate struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Desc   string   `json:"desc"`
	Checks []string `json:"checks"`
}

type PolicyGroup struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

type PolicyHostMap struct {
	Host   string `json:"host"`
	Policy string `json:"policy"`
	Checks string `json:"checks"`
}

type PolicyDefinition struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Checks []string `json:"checks"`
}

type NotificationSchedule struct {
	Name     string `json:"name"`
	Cron     string `json:"cron"`
	Features string `json:"features"`
}

// CollectorConfigResponse effective collector feature matrix.
type CollectorConfigResponse struct {
	Features []CollectorFeature     `json:"features"`
	Crons    []NotificationSchedule `json:"crons"`
}

type CollectorFeature struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
	Menu    string `json:"menu"`
}
