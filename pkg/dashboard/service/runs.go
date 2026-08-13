package service

import (
	"context"
)

// Runs lists recent persisted scan runs.
func (s *Service) Runs(ctx context.Context, limit int) (*RunsResponse, error) {
	rows, err := s.Repo.GetRuns(ctx, limit)
	if err != nil {
		return nil, err
	}
	resp := &RunsResponse{Runs: make([]RunSummary, 0, len(rows))}
	for _, r := range rows {
		durationMs := r.FinishedAt.Sub(r.StartedAt).Milliseconds()
		if durationMs < 0 || r.FinishedAt.IsZero() {
			durationMs = 0
		}
		resp.Runs = append(resp.Runs, RunSummary{
			ID:           r.ID,
			StartedAt:    r.StartedAt,
			FinishedAt:   r.FinishedAt,
			DurationMs:   durationMs,
			Trigger:      r.Trigger,
			TargetID:     r.TargetID,
			TargetHost:   r.TargetHost,
			OverallScore: r.OverallScore,
			TotalPass:    r.TotalPass,
			TotalFail:    r.TotalFail,
		})
	}
	return resp, nil
}
