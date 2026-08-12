package service

import (
	"context"
	"sort"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/repository"
)

// Service reads persisted scan reports for the dashboard APIs.
type Service struct {
	Repo       repository.Repository
	ConfigPath string // optional path to kshieldconfig.toml
}

func New(repo repository.Repository) *Service {
	return &Service{Repo: repo}
}

func NewWithConfig(repo repository.Repository, configPath string) *Service {
	return &Service{Repo: repo, ConfigPath: configPath}
}

func rangeCutoff(rangeKey string) time.Time {
	now := time.Now().UTC()
	switch rangeKey {
	case "24h":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	default:
		return now.Add(-30 * 24 * time.Hour)
	}
}

// latestRunsByTarget returns the newest run per target_id.
func (s *Service) latestRunsByTarget(ctx context.Context) ([]*reportstore.RunRow, error) {
	return s.latestRunsByTargetSince(ctx, time.Time{})
}

const perTargetRunPickLimit = 15

// latestRunsByTargetSince returns newest run per target_id with started_at >= since (if since non-zero).
func (s *Service) latestRunsByTargetSince(ctx context.Context, since time.Time) ([]*reportstore.RunRow, error) {
	targetIDs, err := s.Repo.ListRunTargetIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*reportstore.RunRow, 0, len(targetIDs))
	for _, targetID := range targetIDs {
		runs, err := s.Repo.GetRunsForTarget(ctx, targetID, perTargetRunPickLimit)
		if err != nil {
			return nil, err
		}
		var best *reportstore.RunRow
		for i := range runs {
			r := &runs[i]
			if !since.IsZero() && r.StartedAt.Before(since) {
				continue
			}
			if preferRunRow(r, best) {
				best = r
			}
		}
		if best != nil {
			out = append(out, best)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

func preferRunRow(candidate, current *reportstore.RunRow) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	candChecks := candidate.TotalPass + candidate.TotalFail
	currChecks := current.TotalPass + current.TotalFail
	if candChecks != currChecks {
		return candChecks > currChecks
	}
	if len(candidate.Report) != len(current.Report) {
		return len(candidate.Report) > len(current.Report)
	}
	candReport := runHasReportJSON(candidate)
	currReport := runHasReportJSON(current)
	if candReport != currReport {
		return candReport
	}
	return candidate.StartedAt.After(current.StartedAt)
}

func reportHasLogParserCommand(report map[string]interface{}, command string) bool {
	if report == nil || command == "" {
		return false
	}
	for _, e := range decodeLogParserEntries(report) {
		if logParserEntryCommand(e) == command {
			return true
		}
	}
	return false
}

func reportHasAnyLogParser(report map[string]interface{}) bool {
	return len(decodeLogParserEntries(report)) > 0
}

// latestRunsByTargetWithLogParser returns the newest run per target that includes
// the given log-parser command. Needed when log-parser scans run on a separate
// cron schedule than CIS/PII and would otherwise be hidden by a newer push.
func (s *Service) latestRunsByTargetWithLogParser(ctx context.Context, command string) ([]*reportstore.RunRow, error) {
	targetIDs, err := s.Repo.ListRunTargetIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*reportstore.RunRow, 0, len(targetIDs))
	for _, targetID := range targetIDs {
		runs, err := s.Repo.GetRunsForTarget(ctx, targetID, perTargetRunPickLimit)
		if err != nil {
			return nil, err
		}
		for i := range runs {
			r := &runs[i]
			if reportHasLogParserCommand(r.Report, command) {
				out = append(out, r)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

func (s *Service) latestRunsByTargetWithInactiveUsers(ctx context.Context) ([]*reportstore.RunRow, error) {
	return s.latestRunsByTargetWithLogParser(ctx, cons.LogParserCMD_InactiveUser)
}

func runHasReportJSON(r *reportstore.RunRow) bool {
	if r == nil || len(r.Report) == 0 {
		return false
	}
	if r.TotalPass+r.TotalFail > 0 || r.OverallScore > 0 {
		return true
	}
	for _, key := range []string{"Postgres Report", "HBA Report", "SSL Report", "Log Parser Summary", "Users Report"} {
		if _, ok := r.Report[key]; ok {
			return true
		}
	}
	return false
}
