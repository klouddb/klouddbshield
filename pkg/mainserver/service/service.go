package service

import (
	"context"
	"fmt"
	"time"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/repository"
)

// Service contains main-server business logic over the storage repository.
type Service struct {
	Repo repository.Repository
}

// New creates a main-server service.
func New(repo repository.Repository) *Service {
	return &Service{Repo: repo}
}

func (s *Service) requireRepo() error {
	if s == nil || s.Repo == nil {
		return fmt.Errorf("main database not initialized")
	}
	return nil
}

// StoreScanResult persists a collector scan payload.
func (s *Service) StoreScanResult(ctx context.Context, req ScanDataRequest) error {
	if err := s.requireRepo(); err != nil {
		return err
	}
	report := req.Report
	if report == nil {
		report = map[string]interface{}{}
	}
	pg := &postgresdb.Postgres{
		Host:   req.ScanRun.TargetHost,
		Port:   req.ScanRun.TargetPort,
		DBName: req.ScanRun.TargetDB,
	}
	if req.Data.GucSettings != nil && len(req.Data.GucSettings.Settings) > 0 {
		serverName := req.Node.Name
		if serverName == "" {
			serverName = req.ScanRun.TargetHost
		}
		if err := s.Repo.UpsertServerGucSnapshot(ctx,
			reportstore.GucTargetID(pg),
			serverName,
			req.Node.ID,
			req.Data.GucSettings.Settings,
		); err != nil {
			return err
		}
	}
	_, err := s.Repo.PersistScanResult(ctx, report, reportstore.ScanResultMeta{
		RunMeta: reportstore.RunMeta{
			Trigger:     req.ScanRun.Trigger,
			RunnerName:  "ciscollector",
			FeaturesRun: req.ScanRun.Features,
			Postgres:    pg,
			StartedAt:   req.ScanRun.StartedAt,
			FinishedAt:  req.ScanRun.FinishedAt,
			RunStatus:   req.ScanRun.RunStatus,
		},
		NodeID:       req.Node.ID,
		Hostname:     req.Node.Name,
		ErrorMessage: req.ScanRun.ErrorMessage,
	})
	return err
}

// PersistPIIReport stores PII scan results for a target.
func (s *Service) PersistPIIReport(ctx context.Context, pg *postgresdb.Postgres, piiJSON map[string]interface{}) error {
	if err := s.requireRepo(); err != nil {
		return err
	}
	return s.Repo.PersistPIIReport(ctx, pg, piiJSON)
}

// PersistBackupComplianceReport stores backup compliance scan results for a postgres target.
func (s *Service) PersistBackupComplianceReport(ctx context.Context, meta reportstore.BackupComplianceReportMeta, reportJSON map[string]interface{}) error {
	if err := s.requireRepo(); err != nil {
		return err
	}
	return s.Repo.PersistBackupComplianceReport(ctx, meta, reportJSON)
}

// ScanDataRequest is the v2 collector scan payload.
type ScanDataRequest struct {
	SchemaVersion string
	Node          ScanNodeInfo
	Timestamp     time.Time
	Data          ScanNodeData
	ScanRun       ScanRunMeta
	Report        map[string]interface{}
}

type ScanNodeInfo struct {
	ID   string
	Name string
}

type ScanNodeData struct {
	GucSettings *GucSettingsPayload
}

type GucSettingsPayload struct {
	Settings map[string]string
}

type ScanRunMeta struct {
	Trigger      string
	Features     []string
	TargetHost   string
	TargetPort   string
	TargetDB     string
	RunStatus    string
	ErrorMessage string
	StartedAt    time.Time
	FinishedAt   time.Time
}
