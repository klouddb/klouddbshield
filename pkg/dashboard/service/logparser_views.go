package service

import (
	"fmt"
	"strconv"
	"strings"

	cons "github.com/klouddb/klouddbshield/pkg/const"
)

// LogParserCommandView is one log parser command result for API and host modules.
type LogParserCommandView struct {
	Command     string               `json:"command"`
	Title       string               `json:"title"`
	ParseStatus string               `json:"parseStatus"`
	Result      string               `json:"result"`
	Status      string               `json:"status"`
	DetailType  string               `json:"detailType,omitempty"`
	DetailRows  []LogParserDetailRow `json:"detailRows,omitempty"`
	DetailText  string               `json:"detailText,omitempty"`
}

// LogParserDetailRow is a label/value pair for command-specific findings.
type LogParserDetailRow struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// LogParserScannerResponse is fleet log parser output for one host.
type LogParserScannerResponse struct {
	Host           string                 `json:"host"`
	Available      bool                   `json:"available"`
	Message        string                 `json:"message,omitempty"`
	Commands       []LogParserCommandView `json:"commands"`
	Pass           int                    `json:"pass"`
	Warn           int                    `json:"warn"`
	Fail           int                    `json:"fail"`
	ScanMeta       *LogParserScanMetaView `json:"scanMeta,omitempty"`
	TerminalReport string                 `json:"terminalReport,omitempty"`
}

// LogParserScanMetaView is begin/end filter window + file inventory from collector.
type LogParserScanMetaView struct {
	Begin        string                  `json:"begin,omitempty"`
	End          string                  `json:"end,omitempty"`
	FilesFound   int                     `json:"filesFound"`
	FilesScanned int                     `json:"filesScanned"`
	TotalLines   int64                   `json:"totalLines,omitempty"`
	Duration     string                  `json:"duration,omitempty"`
	Commands     []string                `json:"commands,omitempty"`
	Files        []LogParserFileScanView `json:"files,omitempty"`
}

// LogParserFileScanView is one log file's scan outcome for debugger UI.
type LogParserFileScanView struct {
	FileName   string `json:"fileName"`
	Scanned    bool   `json:"scanned"`
	Status     string `json:"status"`
	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
	SizeBytes  int64  `json:"sizeBytes,omitempty"`
}

func logParserCommandsFromReport(report map[string]interface{}) []LogParserCommandView {
	entries := decodeLogParserEntries(report)
	out := make([]LogParserCommandView, 0, len(entries))
	for _, e := range entries {
		if v, ok := logParserCommandView(e); ok {
			out = append(out, v)
		}
	}
	return out
}

func logParserCommandView(e map[string]interface{}) (LogParserCommandView, bool) {
	cmd := logParserEntryCommand(e)
	if cmd == "" {
		return LogParserCommandView{}, false
	}
	parseStatus := stringField(e, "Parse Status", "parseStatus", "parse_status")
	result := strings.TrimSpace(stringField(e, "Result", "result"))
	if result == "" {
		result = strings.TrimSpace(stringField(e, "text"))
	}
	title := stringField(e, "title", "Title")
	if title == "" {
		title = logParserCommandTitle(cmd)
	}
	status := logParserResultStatus(parseStatus, result, cmd)
	detailType, detailRows, detailText := logParserDetailFromValue(cmd, e["Value"])
	return LogParserCommandView{
		Command:     cmd,
		Title:       title,
		ParseStatus: parseStatus,
		Result:      result,
		Status:      status,
		DetailType:  detailType,
		DetailRows:  detailRows,
		DetailText:  detailText,
	}, true
}

func logParserCommandTitle(cmd string) string {
	switch cmd {
	case cons.LogParserCMD_InactiveUser:
		return "Inactive users"
	case cons.LogParserCMD_UniqueIPs:
		return "Unique client IPs"
	case cons.LogParserCMD_HBAUnusedLines:
		return "Unused HBA lines"
	case cons.LogParserCMD_PasswordLeakScanner:
		return "Password leakage"
	case cons.LogParserCMD_SqlInjectionScan:
		return "SQL injection scan"
	default:
		return cmd
	}
}

func logParserResultStatus(parseStatus, result, command string) string {
	ps := strings.ToLower(parseStatus)
	rs := strings.ToLower(result)
	if strings.Contains(ps, "no lines parsed") {
		return "fail"
	}
	if strings.Contains(rs, "error") || strings.Contains(rs, "issue with result") {
		return "fail"
	}
	switch command {
	case cons.LogParserCMD_PasswordLeakScanner:
		if strings.Contains(rs, "no leaked") {
			return "pass"
		}
		if strings.Contains(rs, "leaked") {
			return "fail"
		}
	case cons.LogParserCMD_InactiveUser:
		if strings.Contains(rs, "inactive users found") {
			return "warn"
		}
		if strings.Contains(rs, "no inactive") || strings.Contains(rs, "no users found") {
			return "pass"
		}
	case cons.LogParserCMD_HBAUnusedLines:
		if strings.Contains(rs, "unused lines found") {
			return "warn"
		}
		if strings.Contains(rs, "no unused") {
			return "pass"
		}
	case cons.LogParserCMD_UniqueIPs:
		if strings.Contains(rs, "no ips") || strings.Contains(rs, "no unique") {
			return "pass"
		}
		if strings.Contains(rs, "unique ips found") || strings.Contains(rs, "ips found") {
			return "info"
		}
	case cons.LogParserCMD_SqlInjectionScan:
		if strings.Contains(rs, "no sql injection") {
			return "pass"
		}
		if strings.Contains(rs, "sql injection") {
			return "warn"
		}
	}
	if strings.HasPrefix(rs, "no ") {
		return "pass"
	}
	return "info"
}

func logParserDetailFromValue(command string, raw interface{}) (detailType string, rows []LogParserDetailRow, text string) {
	if raw == nil {
		return "", nil, ""
	}
	switch command {
	case cons.LogParserCMD_InactiveUser:
		return logParserInactiveDetail(raw)
	case cons.LogParserCMD_UniqueIPs:
		return logParserStringListDetail("unique_ip", "IP address", raw)
	case cons.LogParserCMD_HBAUnusedLines:
		return logParserUnusedHBADetail(raw)
	case cons.LogParserCMD_PasswordLeakScanner:
		return logParserPasswordLeakDetail(raw)
	case cons.LogParserCMD_SqlInjectionScan:
		return logParserStringListDetail(cons.LogParserCMD_SqlInjectionScan, "SQL injection finding", raw)
	default:
		text = trimForTable(fmt.Sprint(raw), 500)
		return command, nil, text
	}
}

func logParserInactiveDetail(raw interface{}) (string, []LogParserDetailRow, string) {
	outer, ok := raw.([]interface{})
	if !ok || len(outer) < 3 {
		return cons.LogParserCMD_InactiveUser, nil, trimForTable(fmt.Sprint(raw), 500)
	}
	labels := []string{"Users from DB", "Users from log", "Inactive users in DB"}
	var rows []LogParserDetailRow
	for i, label := range labels {
		if i >= len(outer) {
			break
		}
		rows = append(rows, LogParserDetailRow{
			Label: label,
			Value: joinInterfaceList(outer[i]),
		})
	}
	return cons.LogParserCMD_InactiveUser, rows, ""
}

func logParserStringListDetail(detailType, label string, raw interface{}) (string, []LogParserDetailRow, string) {
	items := interfaceStringList(raw)
	if len(items) == 0 {
		return detailType, nil, trimForTable(fmt.Sprint(raw), 500)
	}
	rows := make([]LogParserDetailRow, 0, len(items))
	for _, item := range items {
		rows = append(rows, LogParserDetailRow{Label: label, Value: item})
	}
	return detailType, rows, ""
}

func logParserUnusedHBADetail(raw interface{}) (string, []LogParserDetailRow, string) {
	items, ok := raw.([]interface{})
	if !ok {
		return cons.LogParserCMD_HBAUnusedLines, nil, trimForTable(fmt.Sprint(raw), 500)
	}
	var rows []LogParserDetailRow
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		lineNo := stringField(m, "LineNo", "lineNo", "line_no", "LineNumber")
		line := stringField(m, "Line", "line")
		if lineNo == "" && line == "" {
			continue
		}
		label := "Line " + lineNo
		if label == "Line " {
			label = "HBA line"
		}
		rows = append(rows, LogParserDetailRow{Label: label, Value: line})
	}
	return cons.LogParserCMD_HBAUnusedLines, rows, ""
}

func logParserPasswordLeakDetail(raw interface{}) (string, []LogParserDetailRow, string) {
	items, ok := raw.([]interface{})
	if !ok {
		return cons.LogParserCMD_PasswordLeakScanner, nil, trimForTable(fmt.Sprint(raw), 500)
	}
	var rows []LogParserDetailRow
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		password := stringField(m, "Password", "password")
		query := stringField(m, "Query", "query")
		if password == "" && query == "" {
			continue
		}
		rows = append(rows, LogParserDetailRow{
			Label: trimForTable(query, 80),
			Value: password,
		})
	}
	return cons.LogParserCMD_PasswordLeakScanner, rows, ""
}

func joinInterfaceList(raw interface{}) string {
	items := interfaceStringList(raw)
	if len(items) == 0 {
		return "—"
	}
	return strings.Join(items, ", ")
}

func interfaceStringList(raw interface{}) []string {
	list, ok := raw.([]interface{})
	if !ok {
		s := strings.TrimSpace(fmt.Sprint(raw))
		if s == "" || s == "<nil>" {
			return nil
		}
		return []string{s}
	}
	var out []string
	for _, item := range list {
		s := strings.TrimSpace(fmt.Sprint(item))
		if s != "" && s != "<nil>" {
			out = append(out, s)
		}
	}
	return out
}

func logParserRowsFromViews(views []LogParserCommandView) []HostTableRow {
	rows := make([]HostTableRow, 0, len(views))
	for _, v := range views {
		parseStatus := v.ParseStatus
		if parseStatus == "" {
			parseStatus = "—"
		}
		result := v.Result
		if result == "" {
			result = "—"
		}
		rows = append(rows, HostTableRow{
			Cells:  []string{v.Command, parseStatus, result},
			Status: v.Status,
		})
	}
	return rows
}

func summarizeLogParserViews(views []LogParserCommandView) (pass, warn, fail int) {
	for _, v := range views {
		switch v.Status {
		case "pass":
			pass++
		case "warn", "info":
			warn++
		case "fail":
			fail++
		}
	}
	return pass, warn, fail
}

func decodeLogParserScanMeta(report map[string]interface{}) *LogParserScanMetaView {
	if report == nil {
		return nil
	}
	raw, ok := report["Log Parser Scan Meta"]
	if !ok || raw == nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	meta := &LogParserScanMetaView{
		Begin:        stringField(m, "begin", "Begin"),
		End:          stringField(m, "end", "End"),
		Duration:     stringField(m, "duration", "Duration"),
		FilesFound:   intField(m, "files_found", "filesFound"),
		FilesScanned: intField(m, "files_scanned", "filesScanned"),
		TotalLines:   int64Field(m, "total_lines", "totalLines"),
		Commands:     interfaceStringList(m["commands"]),
	}
	if filesRaw, ok := m["files"]; ok {
		meta.Files = decodeLogParserFileScanViews(filesRaw)
	}
	return meta
}

func decodeLogParserTerminalReport(report map[string]interface{}) string {
	if report == nil {
		return ""
	}
	raw, ok := report["Log Parser Terminal Report"]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func decodeLogParserFileScanViews(raw interface{}) []LogParserFileScanView {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]LogParserFileScanView, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, LogParserFileScanView{
			FileName:   stringField(m, "file_name", "fileName", "FileName"),
			Scanned:    boolField(m, "scanned", "Scanned"),
			Status:     stringField(m, "status", "Status"),
			DurationMs: int64Field(m, "duration_ms", "durationMs", "DurationMs"),
			Error:      stringField(m, "error", "Error"),
			SizeBytes:  int64Field(m, "size_bytes", "sizeBytes", "SizeBytes"),
		})
	}
	return out
}

func intField(m map[string]interface{}, keys ...string) int {
	return int(int64Field(m, keys...))
}

func int64Field(m map[string]interface{}, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case int:
				return int64(n)
			case int64:
				return n
			case float64:
				return int64(n)
			case string:
				parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
				if err == nil {
					return parsed
				}
			}
		}
	}
	return 0
}
