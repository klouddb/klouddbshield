package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func hostLabel(run *reportstore.RunRow) string {
	if run == nil {
		return "unknown"
	}
	host := strings.TrimSpace(run.TargetHost)
	port := strings.TrimSpace(run.TargetPort)
	db := strings.TrimSpace(run.TargetDB)
	if host != "" && port != "" && db != "" {
		return host + ":" + port + "/" + db
	}
	if host != "" && port != "" {
		return host + ":" + port
	}
	if host != "" {
		return host
	}
	if run.TargetID != "" {
		parts := strings.Split(run.TargetID, ":")
		if len(parts) >= 4 {
			return parts[1] + ":" + parts[2] + "/" + parts[3]
		}
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "postgres"
}

// instanceLabel returns host:port for grouping databases on one PostgreSQL instance.
func instanceLabel(run *reportstore.RunRow) string {
	if run == nil {
		return "unknown"
	}
	host := strings.TrimSpace(run.TargetHost)
	port := strings.TrimSpace(run.TargetPort)
	if host != "" && port != "" {
		return host + ":" + port
	}
	if run.TargetID != "" {
		parts := strings.Split(run.TargetID, ":")
		if len(parts) >= 3 {
			return parts[1] + ":" + parts[2]
		}
	}
	return ParseHostKey(hostLabel(run)).Instance
}

// ParsedHostKey splits API keys into instance (host:port) and optional database.
type ParsedHostKey struct {
	Instance string
	Database string
	HostKey  string
}

// ParseHostKey parses host API keys and target_id values.
func ParseHostKey(key string) ParsedHostKey {
	key = strings.TrimSpace(key)
	if key == "" {
		return ParsedHostKey{}
	}
	if strings.HasPrefix(key, "postgres:") {
		parts := strings.Split(key, ":")
		if len(parts) >= 4 {
			inst := parts[1] + ":" + parts[2]
			db := parts[3]
			return ParsedHostKey{Instance: inst, Database: db, HostKey: inst + "/" + db}
		}
		if len(parts) >= 3 {
			return ParsedHostKey{Instance: parts[1] + ":" + parts[2]}
		}
	}
	if i := strings.LastIndex(key, "/"); i > 0 {
		inst := key[:i]
		db := key[i+1:]
		if strings.Contains(inst, ":") && db != "" {
			return ParsedHostKey{Instance: inst, Database: db, HostKey: key}
		}
	}
	return ParsedHostKey{Instance: key, HostKey: key}
}

func relativeScanTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return t.Format("2006-01-02")
	}
}

// relativeScanTimeWithDuration shows when the scan finished and how long it took.
func relativeScanTimeWithDuration(startedAt, finishedAt time.Time) string {
	when := finishedAt
	if when.IsZero() {
		when = startedAt
	}
	base := relativeScanTime(when)
	if base == "-" || startedAt.IsZero() || finishedAt.IsZero() {
		return base
	}
	dur := finishedAt.Sub(startedAt)
	if dur < 0 {
		return base
	}
	switch {
	case dur < time.Second:
		return fmt.Sprintf("%s (%dms)", base, dur.Milliseconds())
	case dur < time.Minute:
		return fmt.Sprintf("%s (%.1fs)", base, dur.Seconds())
	default:
		return fmt.Sprintf("%s (%dm)", base, int(dur.Minutes()))
	}
}

// wireCISResult decodes persisted report_json where ManualCheckData is a JSON object,
// not assignable to model.ManualCheckData (interface) via encoding/json alone.
type wireCISResult struct {
	FailReason      interface{}                  `json:"FailReason"`
	Status          string                       `json:"Status"`
	Description     string                       `json:"Description"`
	Control         interface{}                  `json:"Control"`
	Title           string                       `json:"Title"`
	Rationale       string                       `json:"Rationale"`
	References      string                       `json:"References"`
	Procedure       string                       `json:"Procedure"`
	CaseFailReason  map[string]*model.CaseResult `json:"CaseFailReason"`
	ManualCheckData json.RawMessage              `json:"ManualCheckData"`
	Critical        bool                         `json:"Critical"`
}

func (w wireCISResult) toModel() model.Result {
	r := model.Result{
		Status:         w.Status,
		Description:    w.Description,
		Control:        wireString(w.Control),
		Title:          w.Title,
		Rationale:      w.Rationale,
		References:     w.References,
		Procedure:      w.Procedure,
		CaseFailReason: w.CaseFailReason,
		Critical:       w.Critical,
		FailReason:     wireString(w.FailReason),
	}
	if len(w.ManualCheckData) > 0 && string(w.ManualCheckData) != "null" {
		var chk model.ManualCheckTableDescriptionAndList
		if err := json.Unmarshal(w.ManualCheckData, &chk); err == nil &&
			(chk.Table != nil || len(chk.List) > 0 || strings.TrimSpace(chk.Description) != "") {
			r.ManualCheckData = chk
		}
	}
	return r
}

func wireString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprint(x)
	case int:
		return fmt.Sprintf("%d", x)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func decodeCISResults(report map[string]interface{}) []model.Result {
	raw, ok := report["Postgres Report"]
	if !ok {
		return nil
	}
	m, ok := asMap(raw)
	if !ok {
		return nil
	}
	res, ok := m["result"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(res)
	if err != nil {
		return nil
	}
	var wire []wireCISResult
	if err := json.Unmarshal(b, &wire); err != nil {
		return nil
	}
	out := make([]model.Result, len(wire))
	for i, w := range wire {
		out[i] = w.toModel()
	}
	return out
}

func decodeHBAResults(report map[string]interface{}) []model.HBAScannerResult {
	raw, ok := report["HBA Report"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var out []model.HBAScannerResult
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func decodeSSLResults(report map[string]interface{}) *model.SSLScanResult {
	if report == nil {
		return nil
	}
	raw, ok := report["SSL Report"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var out model.SSLScanResult
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	if len(out.Cells) == 0 && len(out.SSLParams) == 0 && len(out.HBALines) == 0 {
		return nil
	}
	return &out
}

// summarizeCISResults counts Pass/Fail rows and compliance percent.
func summarizeCISResults(results []model.Result) (pass, fail int, score float64) {
	for _, r := range results {
		if strings.EqualFold(r.Status, "Pass") {
			pass++
		} else if strings.EqualFold(r.Status, "Fail") {
			fail++
		}
	}
	total := pass + fail
	if total > 0 {
		score = float64(pass) / float64(total) * 100
	}
	return pass, fail, score
}

// runCISSummary prefers denormalized DB columns; falls back to report_json.result[].
func runCISSummary(run *reportstore.RunRow) (pass, fail int, score float64) {
	if run == nil {
		return 0, 0, 0
	}
	if run.TotalPass+run.TotalFail > 0 {
		pass, fail = run.TotalPass, run.TotalFail
		score = run.OverallScore
		if score <= 0 && pass+fail > 0 {
			score = float64(pass) / float64(pass+fail) * 100
		}
		return pass, fail, score
	}
	return summarizeCISResults(decodeCISResults(run.Report))
}

func countFailedCIS(results []model.Result) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Status, "Fail") {
			n++
		}
	}
	return n
}

func countCriticalFails(results []model.Result) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Status, "Fail") && r.Critical {
			n++
		}
	}
	return n
}

func compliancePct(score float64, pass, fail int) string {
	if score > 0 {
		return fmt.Sprintf("%.0f%%", score)
	}
	total := pass + fail
	if total == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", float64(pass)/float64(total)*100)
}

func compliancePctFromRun(run *reportstore.RunRow) string {
	p, f, sc := runCISSummary(run)
	return compliancePct(sc, p, f)
}

func hostStatus(score float64, failCount int) string {
	if failCount == 0 && score >= 90 {
		return "Passing"
	}
	if failCount == 0 && score >= 70 {
		return "Advisory"
	}
	if failCount > 0 || (score > 0 && score < 70) {
		return "Failing"
	}
	if score > 0 {
		return "Advisory"
	}
	return "Advisory"
}

func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func gradeFromHealth(health int) (grade, color string) {
	switch {
	case health >= 90:
		return "A", "var(--success)"
	case health >= 80:
		return "B+", "var(--success)"
	case health >= 70:
		return "B", "var(--warning)"
	case health >= 60:
		return "C", "var(--warning)"
	default:
		return "D", "var(--danger)"
	}
}
