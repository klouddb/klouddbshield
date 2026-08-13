package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func parseHostPort(serverID string) (host, port string) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return "", ""
	}
	if i := strings.LastIndex(serverID, ":"); i > 0 {
		return serverID[:i], serverID[i+1:]
	}
	return serverID, ""
}

// hostMatchesServerID matches API server ids to a scan run (target_id, host:port, db name, etc.).
func hostMatchesServerID(r *reportstore.RunRow, serverID string) bool {
	if r == nil {
		return false
	}
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return false
	}
	if r.TargetID == serverID {
		return true
	}
	if strings.EqualFold(hostLabel(r), serverID) {
		return true
	}
	if strings.EqualFold(r.TargetDB, serverID) {
		return true
	}
	if strings.EqualFold(r.TargetHost, serverID) {
		return true
	}
	if i := strings.LastIndex(r.TargetID, ":"); i >= 0 && i < len(r.TargetID)-1 {
		if strings.EqualFold(r.TargetID[i+1:], serverID) {
			return true
		}
	}
	wantHost, wantPort := parseHostPort(serverID)
	if wantPort != "" {
		return strings.EqualFold(r.TargetHost, wantHost) && r.TargetPort == wantPort
	}
	return false
}

func (s *Service) resolveRunForHost(ctx context.Context, serverID string) (*reportstore.RunRow, error) {
	run, err := s.Repo.GetLatestRun(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if run != nil {
		return run, nil
	}
	runs, err := s.latestRunsByTarget(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		if hostMatchesServerID(r, serverID) {
			return r, nil
		}
	}
	if s.Repo != nil {
		snapshots, err := s.Repo.ListServerGucSnapshots(ctx)
		if err == nil {
			for _, snap := range snapshots {
				if !strings.EqualFold(gucSnapshotHostLabel(snap), serverID) {
					continue
				}
				run, err := s.Repo.GetLatestRun(ctx, snap.TargetID)
				if err != nil {
					return nil, err
				}
				if run != nil {
					return run, nil
				}
			}
		}
	}
	return nil, nil
}

// resolveRunForHostWithLogParser returns the newest run for the host that has
// structured Log Parser Summary entries. Needed because PII-only pushes insert a
// newer scan_results row with empty report_json and would otherwise hide log parser.
func (s *Service) resolveRunForHostWithLogParser(ctx context.Context, serverID string) (*reportstore.RunRow, error) {
	base, err := s.resolveRunForHost(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if base != nil && reportHasAnyLogParser(base.Report) {
		return base, nil
	}
	if base != nil && base.TargetID != "" {
		runs, err := s.Repo.GetRunsForTarget(ctx, base.TargetID, perTargetRunPickLimit)
		if err != nil {
			return nil, err
		}
		for i := range runs {
			if reportHasAnyLogParser(runs[i].Report) {
				return &runs[i], nil
			}
		}
	}
	targetIDs, err := s.Repo.ListRunTargetIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, targetID := range targetIDs {
		runs, err := s.Repo.GetRunsForTarget(ctx, targetID, perTargetRunPickLimit)
		if err != nil {
			return nil, err
		}
		for i := range runs {
			r := &runs[i]
			if !hostMatchesServerID(r, serverID) {
				continue
			}
			if reportHasAnyLogParser(r.Report) {
				return r, nil
			}
		}
	}
	return base, nil
}

// HostReport builds structured modules for the host detail page from SQLite report_json.
func (s *Service) HostReport(ctx context.Context, serverID string) (*HostReportResponse, error) {
	run, err := s.resolveRunForHost(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if run == nil {
		return nil, nil
	}

	cis := decodeCISResults(run.Report)
	hba := decodeHBAResults(run.Report)
	ssl := decodeSSLResults(run.Report)
	failN := countFailedCIS(cis)
	gucTargetID := s.resolveGucSnapshotTargetID(ctx, serverID, run.TargetID)
	drift := hostGucDriftCount(ctx, s, gucTargetID)
	gucDriftDetail := s.buildHostGucDriftView(ctx, serverID, gucTargetID)

	host := HostSummary{
		ID:             run.TargetID,
		Name:           hostLabel(run),
		IP:             run.TargetHost,
		Status:         hostStatus(run.OverallScore, failN),
		CisPct:         compliancePct(run.OverallScore, run.TotalPass, run.TotalFail),
		FailedControls: failN,
		GucDrift:       drift,
		Agent:          "Online",
		LastAudit:      relativeScanTimeWithDuration(run.StartedAt, run.FinishedAt),
		PostgresVer:    decodePostgresVersion(run.Report),
	}

	modules := HostReportModules{
		CisAudit: tableModule(
			[]string{"CIS", "Control", "Result"},
			cisResultRows(cis, nil),
		),
		ConfigAudit: tableModule(
			[]string{"GUC / check", "Title", "Result"},
			cisResultRows(filterCIS(cis, func(r model.Result) bool {
				return cisMatchesAny(r, "guc", "config", "shared_", "log_", "wal_", "fsync", "preload")
			}), nil),
		),
		LoggingGucs: tableModule(
			[]string{"GUC", "Title", "Result"},
			cisResultRows(filterCIS(cis, func(r model.Result) bool {
				return cisMatchesAny(r, "log", "logging", "audit", "pgaudit", "3.")
			}), nil),
		),
		WalReplication: tableModule(
			[]string{"GUC", "Title", "Result"},
			cisResultRows(filterCIS(cis, func(r model.Result) bool {
				return cisMatchesAny(r, "wal", "replication", "archive", "standby", "7.")
			}), nil),
		),
		BackupMonitoring:   emptyModule("Backup audit data not stored in report_json — enable backup history in collector config."),
		XidMonitoring:      emptyModule("XID wraparound data not stored in report_json — run transaction wraparound check."),
		RolesPrivileges:    usersReportSummary(run.Report),
		PgHba:              tableModule([]string{"Check", "Title", "Result"}, hbaRows(hba)),
		SslTls:             tableModule([]string{"Check", "Title", "Result"}, sslRows(cis, hba, ssl)),
		PasswordAudit:      buildPasswordModule(run.Report),
		ConnectionSecurity: connectionSummary(cis, hba),
		PiiResults:         s.buildPiiModule(ctx, run),
		LogParser:          buildLogParserModule(run.Report),
	}

	if len(cis) > 0 {
		modules.CisAudit.Sections = cisSectionScores(cis)
	}

	checks := s.criticalChecksForRun(ctx, run)

	resp := &HostReportResponse{
		Host:           host,
		Modules:        modules,
		GucDriftDetail: gucDriftDetail,
		CriticalChecks: checks,
		CriticalFailed: countCriticalCheckFailures(checks),
		RawKeys:        reportRawKeys(run.Report),
		HtmlExport: &HtmlExportMeta{
			Available:   true,
			RunID:       run.ID,
			OpenURL:     fmt.Sprintf("/api/runs/%s/html", run.ID),
			DownloadURL: fmt.Sprintf("/api/runs/%s/html?download=1", run.ID),
			Hint:        "Full HTML export matches ciscollector klouddbshield_report.html structure.",
		},
		ID:     host.ID,
		Name:   host.Name,
		IP:     host.IP,
		Status: host.Status,
	}
	if len(cis) > 0 {
		resp.PostgresCISResponses = toInterfaceSlice(cis)
	}
	if len(hba) > 0 {
		resp.HBAScanResult = toInterfaceSlice(hba)
	}
	if ssl != nil {
		resp.SSLScanResult = ssl
	}
	if u, ok := run.Report["Users Report"]; ok {
		resp.UserListResult = u
	}
	return resp, nil
}

func buildPasswordModule(report map[string]interface{}) HostModuleView {
	pm := passwordManagerText(report)
	logEntries := decodeLogParserEntries(report)
	var rows []HostTableRow
	if pm != "" {
		rows = append(rows, HostTableRow{
			Cells:  []string{"Password Manager", trimForTable(pm, 120), "Review"},
			Status: "warn",
		})
	}
	for _, e := range logEntries {
		title, _ := e["title"].(string)
		if !strings.Contains(strings.ToLower(title), "password") && !strings.Contains(strings.ToLower(title), "leak") {
			continue
		}
		rows = append(rows, HostTableRow{
			Cells:  []string{"pg_log", title, "See log parser"},
			Status: "fail",
		})
	}
	if len(rows) == 0 {
		return emptyModule("No password audit data in latest scan.")
	}
	return HostModuleView{
		Available: true,
		Columns:   []string{"Source", "Finding", "Action"},
		Rows:      rows,
	}
}

func buildLogParserModule(report map[string]interface{}) HostModuleView {
	views := logParserCommandsFromReport(report)
	if len(views) == 0 {
		return emptyModule("No log parser results in the latest scan. Add log parser commands to scan_commands and configure [collector.logparser].")
	}
	rows := logParserRowsFromViews(views)
	return HostModuleView{
		Available: true,
		Columns:   []string{"Command", "Parse status", "Result"},
		Rows:      rows,
		Callout:   "Open Log parser scan for full command details (inactive_users, unique_ip, unused_lines, password_leak_scanner).",
	}
}

func (s *Service) buildPiiModule(ctx context.Context, run *reportstore.RunRow) HostModuleView {
	if run == nil {
		return emptyModule("PII scan results load from pii_report_json — run PII scanner (menu 4).")
	}
	pii := resolvePIIReport(ctx, s.Repo, run)
	if len(pii) == 0 {
		return emptyModule("PII scan results load from pii_report_json — run PII scanner (menu 4).")
	}
	status, scanMsg, errDetail := decodePIIStatus(pii)
	rows, meta := decodePIIResults(pii)
	if len(rows) > 0 || len(meta) > 0 {
		tableRows := make([]HostTableRow, 0, len(rows)+len(meta))
		for _, r := range rows {
			tableRows = append(tableRows, HostTableRow{
				Cells:  []string{r.Table, r.Column, r.Label, r.Confidence, r.Matched},
				Status: "pass",
			})
		}
		for _, r := range meta {
			tableRows = append(tableRows, HostTableRow{
				Cells:  []string{r.Table, r.Column, r.Label, r.Confidence, "meta"},
				Status: "pass",
			})
		}
		return HostModuleView{
			Available: true,
			Columns:   []string{"Table", "Column", "Label", "Confidence", "Matched"},
			Rows:      tableRows,
		}
	}
	if status != "" && len(rows) == 0 && len(meta) == 0 {
		return HostModuleView{
			Available:   true,
			EmptyReason: piiDisplayMessage(status, scanMsg, errDetail, hostLabel(run)),
		}
	}
	if len(rows) == 0 && len(meta) == 0 {
		return emptyModule("No PII findings in the latest scan.")
	}
	tableRows := make([]HostTableRow, 0, len(rows)+len(meta))
	for _, r := range rows {
		tableRows = append(tableRows, HostTableRow{
			Cells:  []string{r.Table, r.Column, r.Label, r.Confidence, r.Matched},
			Status: "pass",
		})
	}
	for _, r := range meta {
		tableRows = append(tableRows, HostTableRow{
			Cells:  []string{r.Table, r.Column, r.Label, r.Confidence, "meta"},
			Status: "pass",
		})
	}
	return HostModuleView{
		Available: true,
		Columns:   []string{"Table", "Column", "Label", "Confidence", "Matched"},
		Rows:      tableRows,
	}
}

// ServerDetail returns legacy map shape; delegates to HostReport.
func (s *Service) ServerDetail(ctx context.Context, serverID string) (map[string]interface{}, error) {
	resp, err := s.HostReport(ctx, serverID)
	if err != nil || resp == nil {
		return nil, err
	}
	out := map[string]interface{}{
		"id":       resp.ID,
		"name":     resp.Name,
		"ip":       resp.IP,
		"status":   resp.Status,
		"host":     resp.Host,
		"modules":  resp.Modules,
		"raw_keys": resp.RawKeys,
	}
	if resp.HtmlExport != nil {
		out["html_export"] = resp.HtmlExport
	}
	if resp.PostgresCISResponses != nil {
		out["postgres_cis_responses"] = resp.PostgresCISResponses
	}
	if resp.HBAScanResult != nil {
		out["hba_scan_result"] = resp.HBAScanResult
	}
	if resp.SSLScanResult != nil {
		out["ssl_scan_result"] = resp.SSLScanResult
	}
	if resp.UserListResult != nil {
		out["user_list_result"] = resp.UserListResult
	}
	if len(resp.CriticalChecks) > 0 {
		out["critical_checks"] = resp.CriticalChecks
		out["critical_failed"] = resp.CriticalFailed
	}
	out["guc_drift_detail"] = resp.GucDriftDetail
	return out, nil
}

func toInterfaceSlice(v interface{}) []interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out []interface{}
	_ = json.Unmarshal(b, &out)
	return out
}
