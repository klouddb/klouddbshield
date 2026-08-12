package service

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// HbaScannerResponse is fleet HBA check results for one host from latest scan.
type HbaScannerResponse struct {
	Host    string         `json:"host"`
	Checks  []HbaCheckItem `json:"checks"`
	Pass    int            `json:"pass"`
	Fail    int            `json:"fail"`
	Message string         `json:"message,omitempty"`
}

type HbaCheckItem struct {
	N      int    `json:"n"`
	Title  string `json:"title"`
	Desc   string `json:"desc"`
	Status string `json:"status"`
}

// SslScannerResponse is fleet SSL audit results for one host from latest scan.
type SslScannerResponse struct {
	Host      string            `json:"host"`
	Available bool              `json:"available"`
	Message   string            `json:"message,omitempty"`
	Pass      int               `json:"pass"`
	Fail      int               `json:"fail"`
	Warning   int               `json:"warning"`
	Critical  int               `json:"critical"`
	Cells     []SslCheckItem    `json:"cells"`
	SSLParams map[string]string `json:"sslParams,omitempty"`
	HBALines  []string          `json:"hbaLines,omitempty"`
}

type SslCheckItem struct {
	Title   string `json:"title"`
	Desc    string `json:"desc"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// PiiScannerResponse describes PII scan state for a host.
type PiiScannerResponse struct {
	Host            string          `json:"host"`
	Instance        string          `json:"instance,omitempty"`
	Database        string          `json:"database,omitempty"`
	Available       bool            `json:"available"`
	Message         string          `json:"message,omitempty"`
	Status          string          `json:"status,omitempty"`
	ScanMessage     string          `json:"scanMessage,omitempty"`
	ErrorDetail     string          `json:"errorDetail,omitempty"`
	DefaultDatabase string          `json:"defaultDatabase,omitempty"`
	PiiScannedAt    string          `json:"piiScannedAt,omitempty"`
	RunOption       string          `json:"runOption,omitempty"`
	Schema          string          `json:"schema,omitempty"`
	LowConfTables   []string        `json:"lowConfTables,omitempty"`
	Rows            []PiiScannerRow `json:"rows,omitempty"`
	Meta            []PiiScannerRow `json:"meta,omitempty"`
}

type PiiScannerRow struct {
	Table      string `json:"table"`
	Column     string `json:"column"`
	Label      string `json:"label"`
	Confidence string `json:"confidence,omitempty"`
	Matched    string `json:"matched"`
}

// LogParserScanner returns all log parser command findings for a host from report_json.
func (s *Service) LogParserScanner(ctx context.Context, host string) (*LogParserScannerResponse, error) {
	// Prefer a run that actually contains Log Parser Summary. A newer PII-only /
	// empty report_json row must not hide an older successful log-parser push.
	run, err := s.resolveRunForHostWithLogParser(ctx, host)
	if err != nil {
		return nil, err
	}
	resp := &LogParserScannerResponse{Host: host, Commands: []LogParserCommandView{}}
	if run == nil {
		resp.Message = "No scan found for this host. Run collector with log parser commands in scan_commands."
		return resp, nil
	}
	resp.Host = hostLabel(run)
	views := logParserCommandsFromReport(run.Report)
	if len(views) == 0 {
		resp.Message = "No log parser results in report_json. Add inactive_users, unique_ip, unused_lines, or password_leak_scanner to scan_commands."
		return resp, nil
	}
	resp.Available = true
	resp.Commands = views
	resp.Pass, resp.Warn, resp.Fail = summarizeLogParserViews(views)
	return resp, nil
}

// HbaScanner returns HBA Report checks for a host from SQLite.
func (s *Service) HbaScanner(ctx context.Context, host string) (*HbaScannerResponse, error) {
	run, err := s.resolveRunForHost(ctx, host)
	if err != nil {
		return nil, err
	}
	resp := &HbaScannerResponse{Host: host, Checks: []HbaCheckItem{}}
	if run == nil {
		resp.Message = "No scan found for this host. Run: ciscollector -config . -r --json"
		return resp, nil
	}
	resp.Host = hostLabel(run)
	hba := decodeHBAResults(run.Report)
	if len(hba) == 0 {
		resp.Message = "HBA scan not in report_json. Add hba_scanner to cron or run: ciscollector -r --hba-scanner --json"
		return resp, nil
	}
	for _, h := range hba {
		st := strings.ToLower(h.Status)
		if st != "pass" && st != "fail" {
			if strings.EqualFold(h.Status, "Pass") {
				st = "pass"
			} else {
				st = "fail"
			}
		}
		if st == "pass" {
			resp.Pass++
		} else {
			resp.Fail++
		}
		n := h.Control
		if n == 0 {
			n = len(resp.Checks) + 1
		}
		desc := h.Description
		if desc == "" {
			desc = h.Procedure
		}
		resp.Checks = append(resp.Checks, HbaCheckItem{
			N: n, Title: h.Title, Desc: desc, Status: st,
		})
	}
	return resp, nil
}

// SslScanner returns SSL Report checks for a host from SQLite.
func (s *Service) SslScanner(ctx context.Context, host string) (*SslScannerResponse, error) {
	run, err := s.resolveRunForHost(ctx, host)
	if err != nil {
		return nil, err
	}
	resp := &SslScannerResponse{Host: host, Cells: []SslCheckItem{}}
	if run == nil {
		resp.Message = "No scan found for this host. Run: ciscollector -config . -r --json"
		return resp, nil
	}
	resp.Host = hostLabel(run)
	ssl := decodeSSLResults(run.Report)
	if ssl == nil {
		resp.Message = "SSL scan not in report_json. Add ssl_audit to scan_commands or run: ciscollector -r --ssl-check --json"
		return resp, nil
	}
	resp.Available = true
	resp.SSLParams = ssl.SSLParams
	resp.HBALines = ssl.HBALines
	for _, cell := range ssl.Cells {
		if cell == nil {
			continue
		}
		st := normalizeSSLStatus(cell.Status)
		switch st {
		case "pass":
			resp.Pass++
		case "warning":
			resp.Warning++
		case "critical":
			resp.Critical++
		default:
			resp.Fail++
		}
		resp.Cells = append(resp.Cells, SslCheckItem{
			Title:   cell.Title,
			Desc:    cell.Message,
			Status:  st,
			Message: cell.Message,
		})
	}
	return resp, nil
}

func normalizeSSLStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pass":
		return "pass"
	case "warning", "warn":
		return "warning"
	case "critical":
		return "critical"
	default:
		return "fail"
	}
}

// PiiScanner returns PII data from scan_results.pii_report_json when persisted.
func (s *Service) PiiScanner(ctx context.Context, host string) (*PiiScannerResponse, error) {
	run, err := s.resolveRunForHost(ctx, host)
	if err != nil {
		return nil, err
	}
	resp := &PiiScannerResponse{Host: host}
	if run == nil {
		resp.Message = "No CIS/cron run found for " + host + ". Start collector cron (ciscollector -r) with pii_scanner in scan_commands."
		return resp, nil
	}
	resp.Host = hostLabel(run)
	resp.Instance = instanceLabel(run)
	resp.DefaultDatabase = run.TargetDB
	resp.Database = strings.TrimSpace(run.TargetDB)
	if resp.Database == "" {
		resp.Database = ParseHostKey(resp.Host).Database
	}
	if resp.Instance == "" {
		resp.Instance = ParseHostKey(resp.Host).Instance
	}

	piiRun := run
	if len(run.PiiReport) == 0 {
		withPII, err := s.Repo.GetLatestRunWithPII(ctx, run.TargetID)
		if err != nil {
			return nil, err
		}
		if withPII != nil {
			piiRun = withPII
		}
	}
	if piiRun == nil || (len(piiRun.PiiReport) == 0 && piiRun.PiiScannedAt.IsZero()) {
		resp.Message = "No PII scan for " + hostLabel(run) + " yet. Configure [piiscanner] in kshieldconfig.toml and add pii_scanner to scan_commands."
		return resp, nil
	}
	if !piiRun.PiiScannedAt.IsZero() {
		resp.PiiScannedAt = piiRun.PiiScannedAt.UTC().Format(time.RFC3339)
	}

	status, scanMsg, errDetail := decodePIIStatus(piiRun.PiiReport)
	rows, meta := decodePIIResults(piiRun.PiiReport)
	runOpt, schema, lowConf := decodePIIExtras(piiRun.PiiReport)
	resp.RunOption = runOpt
	resp.Schema = schema
	resp.LowConfTables = lowConf
	resp.Status = status
	resp.ScanMessage = scanMsg
	resp.ErrorDetail = errDetail
	resp.Rows = rows
	resp.Meta = meta

	if status != "" {
		resp.Available = piiStatusAvailable(status)
		resp.Message = piiDisplayMessage(status, scanMsg, errDetail, hostLabel(run))
		if len(rows) > 0 || len(meta) > 0 {
			resp.Status = "success"
			resp.ScanMessage = ""
			resp.Rows = rows
			resp.Meta = meta
			resp.Available = true
			resp.Message = ""
			return resp, nil
		}
		return resp, nil
	}

	if len(rows) == 0 && len(meta) == 0 {
		resp.Message = "No PII scan for " + hostLabel(run) + " yet. Configure [piiscanner] in kshieldconfig.toml and add pii_scanner to scan_commands."
		return resp, nil
	}
	resp.Available = true
	return resp, nil
}

func decodePIIStatus(report map[string]interface{}) (status, message, errDetail string) {
	if len(report) == 0 {
		return "", "", ""
	}
	m := report
	if raw, ok := report["PII Report"]; ok {
		if nested, ok := asMap(raw); ok {
			m = nested
		}
	}
	if st, ok := m["status"].(string); ok {
		status = strings.TrimSpace(st)
	}
	if msg, ok := m["message"].(string); ok {
		message = strings.TrimSpace(msg)
	}
	if errText, ok := m["error"].(string); ok {
		errDetail = strings.TrimSpace(errText)
	}
	return status, message, errDetail
}

func piiStatusAvailable(status string) bool {
	switch status {
	case "success", "no_tables", "no_data", "error":
		return true
	default:
		return false
	}
}

func piiDisplayMessage(status, scanMsg, errDetail, host string) string {
	switch status {
	case "error":
		if scanMsg != "" && errDetail != "" {
			return scanMsg + ": " + errDetail
		}
		if errDetail != "" {
			return "PII scan failed on " + host + ": " + errDetail
		}
		if scanMsg != "" {
			return scanMsg
		}
		return "PII scan failed on " + host + "."
	case "no_tables":
		if scanMsg != "" {
			return scanMsg
		}
		return "No tables found in database for PII scan on " + host + "."
	case "no_data":
		if scanMsg != "" {
			return scanMsg
		}
		return "PII scan completed on " + host + " — no PII data found in database."
	default:
		return scanMsg
	}
}

func decodePIIResults(report map[string]interface{}) ([]PiiScannerRow, []PiiScannerRow) {
	if len(report) == 0 {
		return nil, nil
	}
	for _, key := range []string{"PII Report", "PII Scanner Report", "pii_report"} {
		if raw, ok := report[key]; ok {
			return extractPiiRows(raw)
		}
	}
	// pii_report_json column stores high_confidence/meta at top level.
	if _, ok := report["high_confidence"]; ok {
		return extractPiiRows(report)
	}
	if _, ok := report["meta"]; ok {
		return extractPiiRows(report)
	}
	return nil, nil
}

func decodePIIExtras(report map[string]interface{}) (runOption, schema string, lowConf []string) {
	if len(report) == 0 {
		return "", "", nil
	}
	m := report
	if raw, ok := report["PII Report"]; ok {
		if nested, ok := asMap(raw); ok {
			m = nested
		}
	}
	if ro, ok := m["run_option"].(string); ok {
		runOption = ro
	}
	if sc, ok := m["schema"].(string); ok {
		schema = sc
	}
	if raw, ok := m["low_confidence_tables"].([]interface{}); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				lowConf = append(lowConf, s)
			}
		}
	}
	return runOption, schema, lowConf
}

func extractPiiRows(raw interface{}) ([]PiiScannerRow, []PiiScannerRow) {
	m, ok := asMap(raw)
	if !ok {
		return nil, nil
	}
	var dataRows, metaRows []PiiScannerRow
	if tbl, ok := m["high_confidence"]; ok {
		dataRows = append(dataRows, piiFromTable(tbl)...)
	}
	if tbl, ok := m["HighConfidence"]; ok {
		dataRows = append(dataRows, piiFromTable(tbl)...)
	}
	if tbl, ok := m["meta"]; ok {
		metaRows = append(metaRows, piiFromTable(tbl)...)
	}
	if len(dataRows) == 0 {
		dataRows = piiFromTable(raw)
	}
	return dataRows, metaRows
}

func piiFromTable(raw interface{}) []PiiScannerRow {
	t, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	cols, _ := t["columns"].([]interface{})
	rows, _ := t["rows"].([]interface{})
	if len(cols) == 0 || len(rows) == 0 {
		return nil
	}
	colNames := make([]string, len(cols))
	for i, c := range cols {
		colNames[i] = strings.ToLower(fmtCell(c))
	}
	var out []PiiScannerRow
	for _, row := range rows {
		cells, ok := row.([]interface{})
		if !ok {
			continue
		}
		pr := PiiScannerRow{}
		for i, cell := range cells {
			if i >= len(colNames) {
				break
			}
			v := fmtCell(cell)
			switch colNames[i] {
			case "table", "table_name":
				pr.Table = v
			case "column", "column_name":
				pr.Column = v
			case "label", "entity", "pii_type":
				pr.Label = v
			case "confidence", "conf":
				pr.Confidence = v
			case "matched", "match", "count":
				pr.Matched = v
			}
		}
		if pr.Table != "" || pr.Column != "" {
			out = append(out, pr)
		}
	}
	return out
}

func fmtCell(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}
