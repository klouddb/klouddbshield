package mainserverclient

import (
	"context"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

// PiiReportRequest is posted to /api/collector/pii after a PII scan.
type PiiReportRequest struct {
	SchemaVersion string                 `json:"schema_version"`
	Node          NodeInfo               `json:"node"`
	Timestamp     time.Time              `json:"timestamp"`
	TargetHost    string                 `json:"target_host"`
	TargetPort    string                 `json:"target_port"`
	TargetDB      string                 `json:"target_db"`
	PiiReport     map[string]interface{} `json:"pii_report"`
	ScannedAt     time.Time              `json:"scanned_at"`
}

// PushPiiReport stores PII scan JSON in main-server runs.pii_report_json.
func PushPiiReport(ctx context.Context, cnf *config.Config, client *Client, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error {
	if cnf == nil || client == nil || pg == nil || len(piiJSON) == 0 {
		return nil
	}
	h := reportstore.ResolveTargetHost(pg.Host, client.Hostname())
	port := pg.Port
	if port == "" {
		port = "5432"
	}
	dbName := pg.DBName
	if dbName == "" {
		dbName = "postgres"
	}
	req := PiiReportRequest{
		SchemaVersion: "v1",
		Timestamp:     time.Now().UTC(),
		TargetHost:    h,
		TargetPort:    port,
		TargetDB:      dbName,
		PiiReport:     piiJSON,
		ScannedAt:     time.Now().UTC(),
	}
	req.Node = NodeInfo{
		ID:   client.NodeID(),
		Name: client.Hostname(),
		IP:   h,
	}
	req.Node.AgentConfig.Agent.ID = client.NodeID()
	req.Node.AgentConfig.Server.URL = cnf.MainServer.URL
	req.Node.AgentConfig.Server.Token = cnf.MainServer.Token
	req.Node.AgentConfig.Node.Hostname = client.Hostname()
	req.Node.AgentConfig.Node.IP = h
	return client.send(ctx, "/api/collector/pii", req)
}
