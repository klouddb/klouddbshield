package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

// BackupComplianceReportRequest is the backup compliance payload from ciscollector.
type BackupComplianceReportRequest struct {
	SchemaVersion          string                 `json:"schema_version"`
	Node                   NodeInfo               `json:"node"`
	Timestamp              time.Time              `json:"timestamp"`
	TargetID               string                 `json:"target_id"`
	TargetHost             string                 `json:"target_host"`
	TargetPort             string                 `json:"target_port"`
	TargetDB               string                 `json:"target_db"`
	Trigger                string                 `json:"trigger"`
	BackupComplianceReport map[string]interface{} `json:"backup_compliance_report"`
	ScannedAt              time.Time              `json:"scanned_at"`
}

func (a *App) backupComplianceDataPostHandler(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	var req BackupComplianceReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != "v1" {
		http.Error(w, "unsupported schema", http.StatusBadRequest)
		return
	}
	if !collectorBodyTokenAllowed(req.Node.AgentConfig.Server.Token, a.ServerConfig.Token) {
		http.Error(w, "Token not matched", http.StatusBadRequest)
		return
	}
	if len(req.BackupComplianceReport) == 0 {
		http.Error(w, "backup_compliance_report is required", http.StatusBadRequest)
		return
	}
	if a.Svc == nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	host := strings.TrimSpace(req.TargetHost)
	port := strings.TrimSpace(req.TargetPort)
	dbName := strings.TrimSpace(req.TargetDB)
	if host == "" {
		if h, ok := req.BackupComplianceReport["host"].(string); ok {
			// host may be "localhost:5432"
			parts := strings.Split(h, ":")
			if len(parts) >= 1 {
				host = parts[0]
			}
			if len(parts) >= 2 && port == "" {
				port = parts[1]
			}
		}
	}
	if port == "" {
		port = "5432"
	}
	pg := &postgresdb.Postgres{Host: host, Port: port, DBName: dbName}
	meta := reportstore.BackupComplianceReportMeta{
		NodeID:   req.Node.ID,
		Hostname: req.Node.Name,
		Trigger:  strings.TrimSpace(req.Trigger),
		Postgres: pg,
	}
	if err := a.Svc.PersistBackupComplianceReport(r.Context(), meta, req.BackupComplianceReport); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
