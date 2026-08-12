package mainserverclient

import (
	"context"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

// BackupComplianceReportRequest is posted to /api/collector/backup-compliance.
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

// PushBackupComplianceReport stores backup compliance JSON on main-server.
func PushBackupComplianceReport(ctx context.Context, cnf *config.Config, client *Client, pg *postgresdb.Postgres, reportJSON map[string]interface{}, trigger string) error {
	if cnf == nil || client == nil || pg == nil || len(reportJSON) == 0 {
		return nil
	}

	port := pg.Port
	if port == "" {
		port = "5432"
	}
	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		trigger = "cron"
	}
	now := time.Now().UTC()
	host := reportstore.ResolveTargetHost(pg.Host, client.Hostname())
	pgResolved := *pg
	pgResolved.Host = host

	req := BackupComplianceReportRequest{
		SchemaVersion:          "v1",
		Timestamp:              now,
		TargetID:               reportstore.TargetID(&pgResolved),
		TargetHost:             host,
		TargetPort:             port,
		TargetDB:               pg.DBName,
		Trigger:                trigger,
		BackupComplianceReport: reportJSON,
		ScannedAt:              now,
		Node: NodeInfo{
			ID:   client.NodeID(),
			Name: client.Hostname(),
			IP:   client.Hostname(),
		},
	}
	req.Node.AgentConfig.Agent.ID = client.NodeID()
	req.Node.AgentConfig.Server.URL = cnf.MainServer.URL
	req.Node.AgentConfig.Server.Token = cnf.MainServer.Token
	req.Node.AgentConfig.Node.Hostname = client.Hostname()
	req.Node.AgentConfig.Node.IP = client.Hostname()
	return client.send(ctx, "/api/collector/backup-compliance", req)
}
