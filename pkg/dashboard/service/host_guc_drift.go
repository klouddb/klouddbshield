package service

import (
	"context"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/postgresconfig"
)

func (s *Service) resolveGucSnapshotTargetID(ctx context.Context, serverID, runTargetID string) string {
	if s == nil || s.Repo == nil {
		return runTargetID
	}
	serverID = strings.TrimSpace(serverID)
	snapshots, err := s.Repo.ListServerGucSnapshots(ctx)
	if err != nil {
		return runTargetID
	}
	for _, snap := range snapshots {
		if serverID != "" && strings.EqualFold(gucSnapshotHostLabel(snap), serverID) {
			return snap.TargetID
		}
	}
	if runTargetID != "" {
		for _, snap := range snapshots {
			if snap.TargetID == runTargetID {
				return runTargetID
			}
		}
	}
	return runTargetID
}

func (s *Service) buildHostGucDriftView(ctx context.Context, serverID, targetID string) HostGucDriftView {
	out := HostGucDriftView{Available: false, Status: "no_baseline"}
	if s == nil || s.Repo == nil {
		out.EmptyReason = "Database not configured."
		return out
	}
	base, err := s.resolveEffectiveGucBaseline(ctx)
	if err != nil {
		out.EmptyReason = "Failed to load baseline."
		return out
	}
	if len(base.Settings) == 0 || postgresconfig.CountGucSettings(base.Settings) == 0 {
		out.EmptyReason = "Pick a reference host on the GUC drift page."
		return out
	}
	out.BaselineLabel = base.Label
	if base.Host != "" {
		out.BaselineLabel = base.Host
	}
	out.Available = true

	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		out.Status = "no_snapshot"
		out.EmptyReason = "No SHOW ALL snapshot for this host yet."
		return out
	}

	ignoreIdx := reportstore.GucIgnoreIndex{Hosts: map[string]bool{}, Gucs: map[string]map[string]bool{}}
	if ignores, err := s.Repo.ListGucIgnores(ctx); err == nil {
		ignoreIdx = reportstore.BuildGucIgnoreIndex(ignores)
	}
	if ignoreIdx.HostIgnored(targetID) {
		out.Status = "ignored"
		out.HostIgnored = true
		out.EmptyReason = "This host is ignored from GUC drift findings."
		return out
	}

	if base.Source == "host" &&
		(targetID == base.TargetID ||
			reportstore.GucInstanceKey(targetID) == reportstore.GucInstanceKey(base.TargetID)) {
		out.Status = "matched"
		out.EmptyReason = "This host is the reference baseline."
		return out
	}

	live, host, _, err := s.Repo.GetServerGucSnapshot(ctx, targetID)
	if err != nil {
		out.Status = "no_snapshot"
		out.EmptyReason = "Failed to load GUC snapshot."
		return out
	}
	if len(live) == 0 {
		out.Status = "no_snapshot"
		out.EmptyReason = "No SHOW ALL snapshot for this host yet."
		return out
	}
	if host == "" {
		host = strings.TrimSpace(serverID)
	}

	rows, driftCount, missingCount, ignoredCount, verUpd, verNew, verRem := gucDriftRowsForHost(host, targetID, base.Settings, live, ignoreIdx)
	out.DriftCount = driftCount
	out.MissingCount = missingCount
	out.IgnoredCount = ignoredCount
	out.VersionUpdatedCount = verUpd
	out.VersionNewCount = verNew
	out.VersionRemovedCount = verRem
	out.BaselineMajor = postgresconfig.ResolveGucMajor(base.Settings)
	out.PostgresMajor = postgresconfig.ResolveGucMajor(live)
	out.Rows = rows
	if driftCount == 0 && missingCount == 0 {
		out.Status = "matched"
		out.EmptyReason = "All baseline keys match live SHOW ALL."
		return out
	}
	if driftCount > 0 {
		out.Status = "drifted"
	} else {
		out.Status = "missing"
	}
	return out
}

func gucDriftRowsForHost(host, targetID string, baseline, live map[string]string, ignoreIdx reportstore.GucIgnoreIndex) ([]GucDriftRow, int, int, int, int, int, int) {
	var rows []GucDriftRow
	driftCount, missingCount, ignoredCount := 0, 0, 0
	verUpd, verNew, verRem := 0, 0, 0
	for _, row := range postgresconfig.CompareAgainstBaseline(baseline, live) {
		switch row.Status {
		case postgresconfig.DriftDiff, postgresconfig.DriftMissing,
			postgresconfig.DriftVersionUpdated, postgresconfig.DriftVersionNew, postgresconfig.DriftVersionRemoved:
			ignored := ignoreIdx.GucIgnored(targetID, row.GUC)
			rows = append(rows, GucDriftRow{
				Host: host, TargetID: targetID, Guc: row.GUC,
				Live: row.Live, Baseline: row.Baseline, Status: string(row.Status),
				Ignored: ignored,
			})
			if ignored {
				ignoredCount++
				continue
			}
			switch row.Status {
			case postgresconfig.DriftDiff:
				driftCount++
			case postgresconfig.DriftMissing:
				missingCount++
			case postgresconfig.DriftVersionUpdated:
				verUpd++
			case postgresconfig.DriftVersionNew:
				verNew++
			case postgresconfig.DriftVersionRemoved:
				verRem++
			}
		}
	}
	return rows, driftCount, missingCount, ignoredCount, verUpd, verNew, verRem
}
