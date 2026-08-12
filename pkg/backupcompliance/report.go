package backupcompliance

import (
	"strings"
	"time"
)

// Policy is the allowed backup window for a server.
type Policy struct {
	AllowedStart string   `json:"allowed_start"`
	AllowedEnd   string   `json:"allowed_end"`
	AllowedDays  []string `json:"allowed_days,omitempty"` // empty = every day
	Timezone     string   `json:"timezone,omitempty"`     // IANA; empty = Local
}

// Summary aggregates backup counts.
// Failed matches extension v_failed_backups: failed | interrupted | auth_failed.
type Summary struct {
	TotalBackups int `json:"total_backups"`
	Successful   int `json:"successful"`
	Failed       int `json:"failed"`
	Running      int `json:"running"`
	Unauthorized int `json:"unauthorized"`
}

// BackupEntry is one backup in the JSON report.
type BackupEntry struct {
	BackendPID       int    `json:"backend_pid"`
	BackendStart     string `json:"backend_start,omitempty"`
	ApplicationName  string `json:"application_name"`
	BackupType       string `json:"backup_type"`
	Database         string `json:"database"`
	User             string `json:"user"`
	ClientAddr       string `json:"client_addr"`
	IsWalSender      bool   `json:"is_walsender"`
	Status           string `json:"status"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	StartTime        string `json:"start_time"`
	EndTime          string `json:"end_time"`
	ErrorMessage     string `json:"error_message"`
	ConnectionCount  int    `json:"connection_count"`
	ComplianceStatus string `json:"compliance_status"`
	DurationSeconds  int    `json:"duration_seconds"`
}

// Report is the payload pushed to main-server.
type Report struct {
	Host      string        `json:"host"`
	ScannedAt string        `json:"scanned_at"`
	Policy    Policy        `json:"policy"`
	Summary   Summary       `json:"summary"`
	Backups   []BackupEntry `json:"backups"`
}

// IsFailedStatus reports whether status is an unsuccessful attempt per the extension
// (v_failed_backups: failed, interrupted, auth_failed).
func IsFailedStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "interrupted", "auth_failed", "fail", "error":
		return true
	default:
		return false
	}
}

// IsSuccessStatus reports a completed successful backup.
func IsSuccessStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "succeeded", "ok":
		return true
	default:
		return false
	}
}

// IsRunningStatus reports an in-progress backup capture.
func IsRunningStatus(status string) bool {
	return strings.ToLower(strings.TrimSpace(status)) == "running"
}

// BuildReport converts raw extension rows into a compliance report.
func BuildReport(host string, policy Policy, rows []RawBackup, scannedAt time.Time) Report {
	host = strings.TrimSpace(host)
	if scannedAt.IsZero() {
		scannedAt = time.Now().UTC()
	}
	report := Report{
		Host:      host,
		ScannedAt: scannedAt.UTC().Format(time.RFC3339),
		Policy:    policy,
		Backups:   make([]BackupEntry, 0, len(rows)),
	}

	for _, r := range rows {
		entry := BackupEntry{
			BackendPID:       r.BackendPID,
			ApplicationName:  r.ApplicationName,
			BackupType:       r.BackupType,
			Database:         r.DatabaseName,
			User:             r.UserName,
			ClientAddr:       r.ClientAddr,
			IsWalSender:      r.IsWalSender,
			Status:           strings.ToLower(strings.TrimSpace(r.Status)),
			ErrorMessage:     r.ErrorMessage,
			ConnectionCount:  r.ConnectionCount,
			ComplianceStatus: "authorized",
		}
		if !r.BackendStart.IsZero() {
			entry.BackendStart = r.BackendStart.UTC().Format(time.RFC3339Nano)
		}
		if r.ExitCode.Valid {
			code := int(r.ExitCode.Int64)
			entry.ExitCode = &code
		}
		if !r.StartTime.IsZero() {
			entry.StartTime = r.StartTime.UTC().Format(time.RFC3339Nano)
			entry.ComplianceStatus = PolicyComplianceStatus(r.StartTime, policy)
		}
		if !r.EndTime.IsZero() {
			entry.EndTime = r.EndTime.UTC().Format(time.RFC3339Nano)
		}
		if !r.StartTime.IsZero() && !r.EndTime.IsZero() && !r.EndTime.Before(r.StartTime) {
			entry.DurationSeconds = int(r.EndTime.Sub(r.StartTime).Seconds())
		}

		report.Summary.TotalBackups++
		switch {
		case IsSuccessStatus(entry.Status):
			report.Summary.Successful++
		case IsFailedStatus(entry.Status):
			report.Summary.Failed++
		case IsRunningStatus(entry.Status):
			report.Summary.Running++
		default:
			// Unknown status with an error message counts as failed.
			if entry.ErrorMessage != "" {
				report.Summary.Failed++
			}
		}
		if entry.ComplianceStatus == "unauthorized" {
			report.Summary.Unauthorized++
		}
		report.Backups = append(report.Backups, entry)
	}
	return report
}

// ReportToMap converts a Report to map[string]interface{} for JSON push/storage.
func ReportToMap(r Report) map[string]interface{} {
	backups := make([]interface{}, 0, len(r.Backups))
	for _, b := range r.Backups {
		m := map[string]interface{}{
			"backend_pid":       b.BackendPID,
			"application_name":  b.ApplicationName,
			"backup_type":       b.BackupType,
			"database":          b.Database,
			"user":              b.User,
			"client_addr":       b.ClientAddr,
			"is_walsender":      b.IsWalSender,
			"status":            b.Status,
			"start_time":        b.StartTime,
			"end_time":          b.EndTime,
			"error_message":     b.ErrorMessage,
			"connection_count":  b.ConnectionCount,
			"compliance_status": b.ComplianceStatus,
			"duration_seconds":  b.DurationSeconds,
		}
		if b.BackendStart != "" {
			m["backend_start"] = b.BackendStart
		}
		if b.ExitCode != nil {
			m["exit_code"] = *b.ExitCode
		}
		backups = append(backups, m)
	}
	return map[string]interface{}{
		"host":       r.Host,
		"scanned_at": r.ScannedAt,
		"policy":     policyToMap(r.Policy),
		"summary": map[string]interface{}{
			"total_backups": r.Summary.TotalBackups,
			"successful":    r.Summary.Successful,
			"failed":        r.Summary.Failed,
			"running":       r.Summary.Running,
			"unauthorized":  r.Summary.Unauthorized,
		},
		"backups": backups,
	}
}

func policyToMap(p Policy) map[string]interface{} {
	m := map[string]interface{}{
		"allowed_start": p.AllowedStart,
		"allowed_end":   p.AllowedEnd,
	}
	if tz := strings.TrimSpace(p.Timezone); tz != "" {
		m["timezone"] = tz
	}
	if len(p.AllowedDays) > 0 {
		days := make([]interface{}, 0, len(p.AllowedDays))
		for _, d := range p.AllowedDays {
			d = strings.TrimSpace(d)
			if d != "" {
				days = append(days, d)
			}
		}
		if len(days) > 0 {
			m["allowed_days"] = days
		}
	}
	return m
}
