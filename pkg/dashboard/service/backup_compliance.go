package service

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/backupcompliance"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

const (
	policySourceCollector = "collector_config"
	policySourceDashboard = "dashboard"
	policySourceNone      = "none"
)

// BackupComplianceSummaryResponse is GET /api/backup-compliance/summary.
type BackupComplianceSummaryResponse struct {
	TotalBackups int                           `json:"total_backups"`
	Success      int                           `json:"success"`
	Failed       int                           `json:"failed"`
	Unauthorized int                           `json:"unauthorized"`
	ByType       map[string]int                `json:"by_type"`
	Hosts        []BackupComplianceHostSummary `json:"hosts"`
	Available    bool                          `json:"available"`
	Message      string                        `json:"message,omitempty"`
}

// BackupComplianceHostSummary is per-host rollup.
type BackupComplianceHostSummary struct {
	Host         string         `json:"host"`
	Total        int            `json:"total"`
	Success      int            `json:"success"`
	Failed       int            `json:"failed"`
	Unauthorized int            `json:"unauthorized"`
	ByType       map[string]int `json:"by_type,omitempty"`
	ScannedAt    string         `json:"scanned_at,omitempty"`
	AllowedStart string         `json:"allowed_start,omitempty"`
	AllowedEnd   string         `json:"allowed_end,omitempty"`
	AllowedDays  []string       `json:"allowed_days,omitempty"`
	Timezone     string         `json:"timezone,omitempty"`
	PolicySource string         `json:"policy_source,omitempty"` // collector_config | dashboard | none
}

// BackupComplianceHistoryResponse is GET /api/backup-compliance/history.
type BackupComplianceHistoryResponse struct {
	Backups      []BackupComplianceHistoryItem `json:"backups"`
	Unauthorized []BackupComplianceHistoryItem `json:"unauthorized"`
	Available    bool                          `json:"available"`
	Message      string                        `json:"message,omitempty"`
}

// BackupComplianceHistoryItem is one flattened backup row for the UI.
type BackupComplianceHistoryItem struct {
	Server           string   `json:"server"`
	BackendPID       int      `json:"backend_pid,omitempty"`
	ApplicationName  string   `json:"application_name"`
	BackupType       string   `json:"backup_type"`
	Database         string   `json:"database"`
	User             string   `json:"user"`
	ClientAddr       string   `json:"client_addr"`
	IsWalSender      bool     `json:"is_walsender,omitempty"`
	Status           string   `json:"status"`
	ExitCode         *int     `json:"exit_code,omitempty"`
	StartTime        string   `json:"start_time"`
	EndTime          string   `json:"end_time"`
	ErrorMessage     string   `json:"error_message"`
	ConnectionCount  int      `json:"connection_count,omitempty"`
	ComplianceStatus string   `json:"compliance_status"`
	DurationSeconds  int      `json:"duration_seconds"`
	AllowedStart     string   `json:"allowed_start,omitempty"`
	AllowedEnd       string   `json:"allowed_end,omitempty"`
	AllowedDays      []string `json:"allowed_days,omitempty"`
	Timezone         string   `json:"timezone,omitempty"`
	PolicySource     string   `json:"policy_source,omitempty"`
}

// BackupComplianceHistoryFilter holds query params for history.
type BackupComplianceHistoryFilter struct {
	Server     string
	BackupType string
	Date       string
	From       string
	To         string
	Status     string
}

// BackupCompliancePolicyResponse is GET/PUT /api/backup-compliance/policy.
type BackupCompliancePolicyResponse struct {
	AllowedStart string   `json:"allowed_start"`
	AllowedEnd   string   `json:"allowed_end"`
	AllowedDays  []string `json:"allowed_days"`
	Timezone     string   `json:"timezone,omitempty"`
	UpdatedAt    string   `json:"updated_at,omitempty"`
	Configured   bool     `json:"configured"`
	Source       string   `json:"source"`
	Hint         string   `json:"hint,omitempty"`
}

// BackupCompliancePolicyRequest is PUT /api/backup-compliance/policy body.
type BackupCompliancePolicyRequest struct {
	AllowedStart string   `json:"allowed_start"`
	AllowedEnd   string   `json:"allowed_end"`
	AllowedDays  []string `json:"allowed_days"`
	Timezone     string   `json:"timezone"`
}

func (s *Service) BackupComplianceSummary(ctx context.Context) (*BackupComplianceSummaryResponse, error) {
	resp := &BackupComplianceSummaryResponse{
		ByType: map[string]int{},
		Hosts:  []BackupComplianceHostSummary{},
	}
	rows, err := s.Repo.ListLatestBackupComplianceReports(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		resp.Message = "No backup compliance data yet. Enable [backup_compliance] on the collector and ensure pg_backup_compliance extension is installed."
		return resp, nil
	}
	resp.Available = true
	for _, row := range rows {
		host := displayBackupHost(row)
		hs := BackupComplianceHostSummary{Host: host, ByType: map[string]int{}}
		if !row.ScannedAt.IsZero() {
			hs.ScannedAt = row.ScannedAt.UTC().Format(time.RFC3339)
		}
		effective, source, err := s.resolveEffectivePolicy(ctx, row.Report)
		if err != nil {
			return nil, err
		}
		hs.AllowedStart = effective.AllowedStart
		hs.AllowedEnd = effective.AllowedEnd
		hs.AllowedDays = effective.AllowedDays
		hs.Timezone = effective.Timezone
		hs.PolicySource = source
		for _, b := range extractBackupEntries(row.Report) {
			resp.TotalBackups++
			hs.Total++
			bt := strings.ToLower(stringField(b, "backup_type"))
			if bt != "" {
				resp.ByType[bt]++
				hs.ByType[bt]++
			}
			st := strings.ToLower(stringField(b, "status"))
			if isFailedStatus(st) {
				resp.Failed++
				hs.Failed++
			} else if isSuccessStatus(st) {
				resp.Success++
				hs.Success++
			}
			compliance := reevaluateCompliance(stringField(b, "start_time"), stringField(b, "compliance_status"), effective)
			if strings.EqualFold(compliance, "unauthorized") {
				resp.Unauthorized++
				hs.Unauthorized++
			}
		}
		resp.Hosts = append(resp.Hosts, hs)
	}
	sort.Slice(resp.Hosts, func(i, j int) bool {
		return resp.Hosts[i].Host < resp.Hosts[j].Host
	})
	return resp, nil
}

func (s *Service) BackupComplianceHistory(ctx context.Context, f BackupComplianceHistoryFilter) (*BackupComplianceHistoryResponse, error) {
	resp := &BackupComplianceHistoryResponse{
		Backups:      []BackupComplianceHistoryItem{},
		Unauthorized: []BackupComplianceHistoryItem{},
	}
	rows, err := s.Repo.ListLatestBackupComplianceReports(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		resp.Message = "No backup compliance data yet."
		return resp, nil
	}
	resp.Available = true

	from, to := historyDateRange(f)
	backupType := strings.ToLower(strings.TrimSpace(f.BackupType))
	statusFilter := strings.ToLower(strings.TrimSpace(f.Status))
	serverFilter := strings.TrimSpace(f.Server)
	if backupType == "all" {
		backupType = ""
	}
	if statusFilter == "all" {
		statusFilter = ""
	}
	if strings.EqualFold(serverFilter, "all") {
		serverFilter = ""
	}

	var all []BackupComplianceHistoryItem
	for _, row := range rows {
		host := displayBackupHost(row)
		if serverFilter != "" && !strings.EqualFold(host, serverFilter) {
			continue
		}
		effective, source, err := s.resolveEffectivePolicy(ctx, row.Report)
		if err != nil {
			return nil, err
		}
		for _, b := range extractBackupEntries(row.Report) {
			compliance := reevaluateCompliance(stringField(b, "start_time"), stringField(b, "compliance_status"), effective)
			item := BackupComplianceHistoryItem{
				Server:           host,
				BackendPID:       backupIntField(b, "backend_pid"),
				ApplicationName:  stringField(b, "application_name"),
				BackupType:       stringField(b, "backup_type"),
				Database:         stringField(b, "database"),
				User:             stringField(b, "user"),
				ClientAddr:       stringField(b, "client_addr"),
				IsWalSender:      backupBoolField(b, "is_walsender"),
				Status:           stringField(b, "status"),
				StartTime:        stringField(b, "start_time"),
				EndTime:          stringField(b, "end_time"),
				ErrorMessage:     stringField(b, "error_message"),
				ConnectionCount:  backupIntField(b, "connection_count"),
				ComplianceStatus: compliance,
				DurationSeconds:  backupIntField(b, "duration_seconds"),
				AllowedStart:     effective.AllowedStart,
				AllowedEnd:       effective.AllowedEnd,
				AllowedDays:      effective.AllowedDays,
				Timezone:         effective.Timezone,
				PolicySource:     source,
			}
			if code, ok := backupOptionalInt(b, "exit_code"); ok {
				item.ExitCode = &code
			}
			if !matchBackupType(item.BackupType, backupType) {
				continue
			}
			if !matchHistoryDate(item.StartTime, from, to) {
				continue
			}
			if !matchHistoryStatus(item, statusFilter) {
				continue
			}
			all = append(all, item)
			if strings.EqualFold(item.ComplianceStatus, "unauthorized") {
				resp.Unauthorized = append(resp.Unauthorized, item)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].StartTime > all[j].StartTime
	})
	sort.Slice(resp.Unauthorized, func(i, j int) bool {
		return resp.Unauthorized[i].StartTime > resp.Unauthorized[j].StartTime
	})
	resp.Backups = all
	return resp, nil
}

func (s *Service) GetBackupCompliancePolicy(ctx context.Context) (*BackupCompliancePolicyResponse, error) {
	stored, updatedAt, err := s.Repo.GetBackupCompliancePolicy(ctx)
	if err != nil {
		return nil, err
	}
	p := backupcompliance.Policy{
		AllowedStart: stored.AllowedStart,
		AllowedEnd:   stored.AllowedEnd,
		AllowedDays:  stored.AllowedDays,
		Timezone:     stored.Timezone,
	}
	resp := &BackupCompliancePolicyResponse{
		AllowedStart: stored.AllowedStart,
		AllowedEnd:   stored.AllowedEnd,
		AllowedDays:  stored.AllowedDays,
		Timezone:     stored.Timezone,
		UpdatedAt:    updatedAt,
		Configured:   backupcompliance.PolicyConfigured(p),
		Source:       policySourceNone,
		Hint:         "Dashboard window is used only when the collector report has no window.",
	}
	if resp.AllowedDays == nil {
		resp.AllowedDays = []string{}
	}
	if resp.Configured {
		resp.Source = policySourceDashboard
	}
	return resp, nil
}

func (s *Service) PutBackupCompliancePolicy(ctx context.Context, req BackupCompliancePolicyRequest) (*BackupCompliancePolicyResponse, error) {
	start := strings.TrimSpace(req.AllowedStart)
	end := strings.TrimSpace(req.AllowedEnd)
	tz := strings.TrimSpace(req.Timezone)
	days := make([]string, 0, len(req.AllowedDays))
	for _, d := range req.AllowedDays {
		d = strings.TrimSpace(d)
		if d != "" {
			days = append(days, d)
		}
	}
	if start != "" || end != "" {
		if _, ok := backupcompliance.ParseClock(start); !ok {
			return nil, fmt.Errorf("allowed_start must be HH:MM")
		}
		if _, ok := backupcompliance.ParseClock(end); !ok {
			return nil, fmt.Errorf("allowed_end must be HH:MM")
		}
	}
	if err := s.Repo.UpsertBackupCompliancePolicy(ctx, reportstore.BackupCompliancePolicyStored{
		AllowedStart: start,
		AllowedEnd:   end,
		AllowedDays:  days,
		Timezone:     tz,
	}); err != nil {
		return nil, err
	}
	return s.GetBackupCompliancePolicy(ctx)
}

// resolveEffectivePolicy: collector config wins when configured; else dashboard DB.
// Reports may include policy.policy_source = collector_config | dashboard | none
// (set by ciscollector so a dashboard fallback is not mislabeled as config).
func (s *Service) resolveEffectivePolicy(ctx context.Context, report map[string]interface{}) (backupcompliance.Policy, string, error) {
	collector := policyFromReport(report)
	srcHint := policySourceFromReport(report)

	stored, _, err := s.Repo.GetBackupCompliancePolicy(ctx)
	if err != nil {
		return backupcompliance.Policy{}, "", err
	}
	dash := backupcompliance.Policy{
		AllowedStart: stored.AllowedStart,
		AllowedEnd:   stored.AllowedEnd,
		AllowedDays:  stored.AllowedDays,
		Timezone:     stored.Timezone,
	}

	// Explicit dashboard stamp from collector (config was empty; used API window).
	if srcHint == policySourceDashboard {
		if backupcompliance.PolicyConfigured(dash) {
			return dash, policySourceDashboard, nil
		}
		if backupcompliance.PolicyConfigured(collector) {
			return collector, policySourceDashboard, nil
		}
		return backupcompliance.Policy{}, policySourceNone, nil
	}

	// Collector kshieldconfig.toml window (or legacy reports with a window and no stamp).
	if srcHint != policySourceDashboard && backupcompliance.PolicyConfigured(collector) {
		return collector, policySourceCollector, nil
	}

	if backupcompliance.PolicyConfigured(dash) {
		return dash, policySourceDashboard, nil
	}
	return backupcompliance.Policy{}, policySourceNone, nil
}

func policySourceFromReport(report map[string]interface{}) string {
	if report == nil {
		return ""
	}
	pol, _ := report["policy"].(map[string]interface{})
	if pol == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(stringField(pol, "policy_source")))
}

func policyFromReport(report map[string]interface{}) backupcompliance.Policy {
	start, end, days, tz := policyWindowFull(report)
	return backupcompliance.Policy{
		AllowedStart: start,
		AllowedEnd:   end,
		AllowedDays:  days,
		Timezone:     tz,
	}
}

func reevaluateCompliance(startTime, storedStatus string, policy backupcompliance.Policy) string {
	if !backupcompliance.PolicyConfigured(policy) {
		if strings.TrimSpace(storedStatus) != "" {
			return storedStatus
		}
		return "authorized"
	}
	t := parseBackupStartTime(startTime)
	if t.IsZero() {
		if strings.TrimSpace(storedStatus) != "" {
			return storedStatus
		}
		return "authorized"
	}
	return backupcompliance.PolicyComplianceStatus(t, policy)
}

func parseBackupStartTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func displayBackupHost(row reportstore.BackupComplianceRow) string {
	if row.Report != nil {
		if h, ok := row.Report["host"].(string); ok && strings.TrimSpace(h) != "" {
			return strings.TrimSpace(h)
		}
	}
	port := row.TargetPort
	if port == "" {
		port = "5432"
	}
	if row.TargetHost != "" {
		return fmt.Sprintf("%s:%s", row.TargetHost, port)
	}
	return row.TargetID
}

func policyWindowFull(report map[string]interface{}) (start, end string, days []string, tz string) {
	if report == nil {
		return "", "", nil, ""
	}
	pol, _ := report["policy"].(map[string]interface{})
	if pol == nil {
		return "", "", nil, ""
	}
	return stringField(pol, "allowed_start"), stringField(pol, "allowed_end"), stringSliceField(pol, "allowed_days"), stringField(pol, "timezone")
}

func stringSliceField(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func extractBackupEntries(report map[string]interface{}) []map[string]interface{} {
	if report == nil {
		return nil
	}
	raw, ok := report["backups"]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	case []map[string]interface{}:
		return v
	default:
		return nil
	}
}

func backupIntField(m map[string]interface{}, key string) int {
	n, ok := backupOptionalInt(m, key)
	if !ok {
		return 0
	}
	return n
}

func backupOptionalInt(m map[string]interface{}, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		if t > int64(math.MaxInt) || t < int64(math.MinInt) {
			return 0, false
		}
		return int(t), true
	case float64:
		n := int64(t)
		if float64(n) != t || n > int64(math.MaxInt) || n < int64(math.MinInt) {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func backupBoolField(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func isFailedStatus(st string) bool {
	switch strings.ToLower(strings.TrimSpace(st)) {
	case "failed", "fail", "error", "interrupted", "auth_failed":
		return true
	default:
		return false
	}
}

func isSuccessStatus(st string) bool {
	switch strings.ToLower(strings.TrimSpace(st)) {
	case "success", "succeeded", "ok":
		return true
	default:
		return false
	}
}

func matchBackupType(got, want string) bool {
	if want == "" {
		return true
	}
	return strings.EqualFold(got, want)
}

func matchHistoryStatus(item BackupComplianceHistoryItem, want string) bool {
	if want == "" {
		return true
	}
	switch want {
	case "unauthorized":
		return strings.EqualFold(item.ComplianceStatus, "unauthorized")
	case "success", "failed":
		st := strings.ToLower(item.Status)
		if want == "failed" {
			return isFailedStatus(st)
		}
		return isSuccessStatus(st)
	default:
		return true
	}
}

func historyDateRange(f BackupComplianceHistoryFilter) (from, to time.Time) {
	now := time.Now().UTC()
	to = now.Add(24 * time.Hour)
	switch strings.ToLower(strings.TrimSpace(f.Date)) {
	case "today":
		y, m, d := now.Date()
		from = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	case "last_7_days", "7d", "":
		from = now.AddDate(0, 0, -7)
	case "last_30_days", "30d", "last_month":
		from = now.AddDate(0, 0, -30)
	case "custom":
		from = parseFlexibleTime(f.From)
		toParsed := parseFlexibleTime(f.To)
		if !toParsed.IsZero() {
			to = toParsed.Add(24 * time.Hour)
		}
		if from.IsZero() {
			from = now.AddDate(0, 0, -30)
		}
	default:
		from = now.AddDate(0, 0, -7)
	}
	return from, to
}

func parseFlexibleTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func matchHistoryDate(startTime string, from, to time.Time) bool {
	if from.IsZero() && to.IsZero() {
		return true
	}
	t := parseFlexibleTime(startTime)
	if t.IsZero() {
		if parsed, err := time.Parse(time.RFC3339Nano, startTime); err == nil {
			t = parsed.UTC()
		} else {
			return true
		}
	}
	if !from.IsZero() && t.Before(from) {
		return false
	}
	if !to.IsZero() && !t.Before(to) {
		return false
	}
	return true
}
