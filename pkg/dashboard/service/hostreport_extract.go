package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
)

func reportRawKeys(report map[string]interface{}) []string {
	if report == nil {
		return nil
	}
	keys := make([]string, 0, len(report))
	for k := range report {
		keys = append(keys, k)
	}
	return keys
}

func cisResultRows(results []model.Result, cols []string) []HostTableRow {
	var rows []HostTableRow
	for _, r := range results {
		status := strings.ToLower(r.Status)
		rows = append(rows, HostTableRow{
			Cells:  []string{r.Control, r.Title, r.Status},
			Status: status,
		})
	}
	return rows
}

func filterCIS(results []model.Result, match func(model.Result) bool) []model.Result {
	var out []model.Result
	for _, r := range results {
		if match(r) {
			out = append(out, r)
		}
	}
	return out
}

func cisMatchesAny(r model.Result, parts ...string) bool {
	blob := strings.ToLower(r.Control + " " + r.Title + " " + r.Description + " " + r.FailReason)
	for _, p := range parts {
		if p != "" && strings.Contains(blob, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func emptyModule(reason string) HostModuleView {
	return HostModuleView{
		Available:   false,
		EmptyReason: reason,
	}
}

func tableModule(cols []string, rows []HostTableRow) HostModuleView {
	if len(rows) == 0 {
		return emptyModule("No matching checks in the latest scan report.")
	}
	return HostModuleView{
		Available: true,
		Columns:   cols,
		Rows:      rows,
	}
}

func decodePostgresVersion(report map[string]interface{}) string {
	raw, ok := report["Postgres Report"]
	if !ok {
		return ""
	}
	m, ok := asMap(raw)
	if !ok {
		return ""
	}
	if v, ok := m["version"].(string); ok {
		return v
	}
	return ""
}

func decodeLogParserEntries(report map[string]interface{}) []map[string]interface{} {
	raw, ok := report["Log Parser Summary"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		var out []map[string]interface{}
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if logParserEntryHasIdentity(m) {
					out = append(out, normalizeLogParserEntry(m))
				}
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []map[string]interface{}{{"title": "Log Parser Summary", "text": v}}
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var arr []map[string]interface{}
		if json.Unmarshal(b, &arr) == nil {
			return arr
		}
		return nil
	}
}

func trimForTable(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// fleetTableDetailText keeps the full finding text and wraps after commas
// so fleet tables can show it line-by-line instead of truncating.
func fleetTableDetailText(primary, fallback string) string {
	s := strings.TrimSpace(primary)
	if s == "" {
		s = strings.TrimSpace(fallback)
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if !strings.Contains(s, "\n") && strings.Contains(s, ", ") {
		s = strings.ReplaceAll(s, ", ", ",\n")
	}
	return s
}

func passwordManagerText(report map[string]interface{}) string {
	raw, ok := report["Password Manager Report"]
	if !ok {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func hbaRows(hba []model.HBAScannerResult) []HostTableRow {
	var rows []HostTableRow
	for _, h := range hba {
		status := strings.ToLower(h.Status)
		detail := h.Description
		if len(h.FailRows) > 0 {
			detail = strings.Join(h.FailRows, "; ")
		}
		rows = append(rows, HostTableRow{
			Cells:  []string{fmt.Sprintf("HBA Check %d", h.Control), h.Title, h.Status},
			Status: status,
		})
		if detail != "" && status == "fail" {
			rows[len(rows)-1].Cells[1] = h.Title + " — " + trimForTable(detail, 120)
		}
	}
	return rows
}

var sslCISControls = map[string]bool{
	"6.7": true, "6.8": true, "6.9": true, "6.10": true,
}

func sslRows(cis []model.Result, hba []model.HBAScannerResult, ssl *model.SSLScanResult) []HostTableRow {
	var rows []HostTableRow
	seen := map[string]bool{}

	appendRow := func(key string, cells []string, status string) {
		if seen[key] {
			return
		}
		seen[key] = true
		rows = append(rows, HostTableRow{Cells: cells, Status: strings.ToLower(status)})
	}

	for _, r := range cis {
		if sslCISControls[r.Control] {
			appendRow("cis:"+r.Control, []string{r.Control, r.Title, r.Status}, r.Status)
		}
	}
	for _, r := range cis {
		if sslCISControls[r.Control] {
			continue
		}
		if !cisMatchesAny(r, "ssl", "tls", "certificate") {
			continue
		}
		key := "cis:" + r.Control
		if r.Control == "" {
			key = "cis:" + r.Title
		}
		appendRow(key, []string{r.Control, r.Title, r.Status}, r.Status)
	}
	for _, h := range hba {
		if !strings.Contains(strings.ToLower(h.Title), "ssl") && !strings.Contains(strings.ToLower(h.Title), "hostssl") {
			continue
		}
		appendRow(fmt.Sprintf("hba:%d", h.Control), []string{fmt.Sprintf("HBA %d", h.Control), h.Title, h.Status}, h.Status)
	}
	if ssl != nil {
		for i, cell := range ssl.Cells {
			if cell == nil {
				continue
			}
			detail := cell.Message
			if detail != "" {
				detail = cell.Title + " — " + detail
			} else {
				detail = cell.Title
			}
			appendRow(fmt.Sprintf("ssl:%d", i), []string{"SSL", detail, cell.Status}, cell.Status)
		}
	}
	return rows
}

func connectionSummary(cis []model.Result, hba []model.HBAScannerResult) HostModuleView {
	rows := []HostTableRow{}
	hbaFail := 0
	for _, h := range hba {
		if strings.EqualFold(h.Status, "Fail") {
			hbaFail++
		}
	}
	if hbaFail > 0 {
		rows = append(rows, HostTableRow{
			Cells:  []string{"pg_hba.conf", "Open / trust / weak rules", fmt.Sprintf("%d failures", hbaFail)},
			Status: "fail",
		})
	}
	for _, r := range cis {
		if cisMatchesAny(r, "connection", "login", "tcp", "host ") && strings.EqualFold(r.Status, "Fail") {
			rows = append(rows, HostTableRow{
				Cells:  []string{"CIS §5", r.Title, "Fail"},
				Status: "fail",
			})
		}
	}
	logReady := "Partial"
	for _, r := range cis {
		if strings.Contains(strings.ToLower(r.Title), "log_line_prefix") && strings.EqualFold(r.Status, "Fail") {
			logReady = "Fail"
		}
	}
	rows = append(rows, HostTableRow{
		Cells:  []string{"Log GUCs", "Ready for pg_log audit", logReady},
		Status: strings.ToLower(logReady),
	})
	if len(rows) == 0 {
		return emptyModule("No connection-related findings in the latest scan.")
	}
	callout := ""
	if logReady == "fail" || logReady == "partial" {
		callout = "Log-readiness may limit pg_log parser attribution until logging GUCs are fixed."
	}
	return HostModuleView{
		Available: true,
		Columns:   []string{"Area", "Check", "Result"},
		Rows:      rows,
		Callout:   callout,
	}
}

func usersReportSummary(report map[string]interface{}) HostModuleView {
	raw, ok := report["Users Report"]
	if !ok {
		return emptyModule("Users Report not in latest scan — run postgres_cis / userlist.")
	}
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return emptyModule("Users Report is empty.")
		}
		return HostModuleView{
			Available: true,
			Summary:   []HostKV{{Key: "Users report", Value: trimForTable(v, 200)}},
		}
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return emptyModule("Could not decode Users Report.")
		}
		return HostModuleView{
			Available: true,
			Summary:   []HostKV{{Key: "Users report", Value: trimForTable(string(b), 200)}},
		}
	}
}

func cisSectionScores(results []model.Result) []HostSectionScore {
	sections := map[string]struct{ pass, total int }{
		"§1 Installation": {},
		"§3 Logging":      {},
		"§5 Connection":   {},
		"§6 GUCs":         {},
	}
	for _, r := range results {
		key := "§6 GUCs"
		blob := strings.ToLower(r.Control + r.Title)
		switch {
		case strings.Contains(blob, "3.") || strings.Contains(blob, "log"):
			key = "§3 Logging"
		case strings.Contains(blob, "5.") || strings.Contains(blob, "connection"):
			key = "§5 Connection"
		case strings.Contains(blob, "1.") || strings.Contains(blob, "install"):
			key = "§1 Installation"
		}
		s := sections[key]
		s.total++
		if strings.EqualFold(r.Status, "Pass") {
			s.pass++
		}
		sections[key] = s
	}
	order := []string{"§1 Installation", "§3 Logging", "§5 Connection", "§6 GUCs"}
	var out []HostSectionScore
	for _, label := range order {
		s := sections[label]
		if s.total == 0 {
			continue
		}
		pct := s.pass * 100 / s.total
		out = append(out, HostSectionScore{Label: label, Pct: pct})
	}
	return out
}
