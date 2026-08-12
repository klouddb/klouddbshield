package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/postgresconfig"
)

type resolvedGucBaseline struct {
	Label    string
	Source   string // host | file | none
	TargetID string
	Host     string
	Settings map[string]string
	Updated  string
	GroupID  string
}

func (s *Service) resolveEffectiveGucBaseline(ctx context.Context) (resolvedGucBaseline, error) {
	return s.resolveGucBaselineForGroup(ctx, "")
}

func (s *Service) resolveGucBaselineForGroup(ctx context.Context, groupID string) (resolvedGucBaseline, error) {
	out := resolvedGucBaseline{Source: "none", Settings: map[string]string{}, GroupID: strings.TrimSpace(groupID)}
	if s == nil || s.Repo == nil {
		return out, nil
	}

	if out.GroupID != "" {
		g, err := s.Repo.GetGucServerGroup(ctx, out.GroupID)
		if err != nil {
			return out, err
		}
		if g == nil {
			return out, fmt.Errorf("group not found")
		}
		out.Label = g.Name
		out.Updated = g.UpdatedAt
		return s.hydrateBaselineFromStored(ctx, out, g.Baseline)
	}

	label, stored, updatedAt, err := s.Repo.GetGucBaseline(ctx)
	if err != nil {
		return out, err
	}
	out.Label = label
	out.Updated = updatedAt
	return s.hydrateBaselineFromStored(ctx, out, stored)
}

func (s *Service) hydrateBaselineFromStored(ctx context.Context, out resolvedGucBaseline, stored map[string]string) (resolvedGucBaseline, error) {
	source := reportstore.GucBaselineSource(stored)
	targetID := reportstore.GucBaselineTargetID(stored)

	if source == reportstore.GucBaselineSourceHost && targetID != "" {
		live, host, _, err := s.Repo.GetServerGucSnapshot(ctx, targetID)
		if err != nil {
			return out, err
		}
		out.Source = reportstore.GucBaselineSourceHost
		out.TargetID = targetID
		out.Host = host
		if out.Host == "" {
			out.Host = out.Label
		}
		if out.Label == "" {
			out.Label = out.Host
		}
		out.Settings = postgresconfig.NormalizeGucSettings(live)
		return out, nil
	}

	settings := postgresconfig.NormalizeGucSettings(reportstore.StripGucBaselineMeta(stored))
	if postgresconfig.CountGucSettings(settings) == 0 {
		return out, nil
	}
	out.Source = reportstore.GucBaselineSourceFile
	if source != "" {
		out.Source = source
	}
	out.Settings = settings
	return out, nil
}

type gucDriftQuery struct {
	GroupID  string
	TargetID string // optional: detail filter
}

func (s *Service) gucDriftFromSnapshots(ctx context.Context) (*GucDriftResponse, error) {
	return s.gucDriftFromSnapshotsQuery(ctx, gucDriftQuery{})
}

func (s *Service) gucDriftFromSnapshotsQuery(ctx context.Context, q gucDriftQuery) (*GucDriftResponse, error) {
	if s.Repo == nil {
		return &GucDriftResponse{}, nil
	}
	base, err := s.resolveGucBaselineForGroup(ctx, q.GroupID)
	if err != nil {
		return nil, err
	}
	snapshots, err := s.Repo.ListServerGucSnapshots(ctx)
	if err != nil {
		return nil, err
	}

	ignoreIdx := reportstore.GucIgnoreIndex{Hosts: map[string]bool{}, Gucs: map[string]map[string]bool{}}
	if ignores, err := s.Repo.ListGucIgnores(ctx); err == nil {
		ignoreIdx = reportstore.BuildGucIgnoreIndex(ignores)
	}

	memberFilter := map[string]bool{}
	groupName := ""
	if q.GroupID != "" {
		g, err := s.Repo.GetGucServerGroup(ctx, q.GroupID)
		if err != nil {
			return nil, err
		}
		if g == nil {
			return nil, fmt.Errorf("group not found")
		}
		groupName = g.Name
		for _, tid := range g.MemberIDs {
			memberFilter[tid] = true
			if key := reportstore.GucInstanceKey(tid); key != "" {
				memberFilter[key] = true
			}
		}
	}

	resp := &GucDriftResponse{
		Stats: GucDriftStats{
			BaselineLabel:    base.Label,
			BaselineKeys:     postgresconfig.CountGucSettings(base.Settings),
			BaselineSource:   base.Source,
			BaselineTargetID: base.TargetID,
			BaselineHost:     base.Host,
			BaselineMajor:    postgresconfig.ResolveGucMajor(base.Settings),
		},
		HostSummaries: []GucDriftHostSummary{},
		Rows:          []GucDriftRow{},
		GroupID:       q.GroupID,
		GroupName:     groupName,
	}

	deduped := dedupeGucSnapshotsByInstance(snapshots)
	filterTarget := strings.TrimSpace(q.TargetID)
	filterInstance := reportstore.GucInstanceKey(filterTarget)

	// No baseline yet: still list group members / fleet hosts so Save group is visible.
	if postgresconfig.CountGucSettings(base.Settings) == 0 {
		for _, snap := range deduped {
			if len(memberFilter) > 0 {
				inst := reportstore.GucInstanceKey(snap.TargetID)
				if !memberFilter[snap.TargetID] && !memberFilter[inst] {
					continue
				}
			} else if q.GroupID != "" {
				// Group selected but no members saved yet.
				continue
			}
			if filterTarget != "" {
				inst := reportstore.GucInstanceKey(snap.TargetID)
				if snap.TargetID != filterTarget && inst != filterInstance && inst != filterTarget {
					continue
				}
			}
			resp.Stats.HostsCompared++
			status := "no_baseline"
			live, _, _, err := s.Repo.GetServerGucSnapshot(ctx, snap.TargetID)
			if err != nil || len(live) == 0 {
				status = "no_snapshot"
			}
			resp.HostSummaries = append(resp.HostSummaries, GucDriftHostSummary{
				Host:        gucSnapshotHostLabel(snap),
				TargetID:    snap.TargetID,
				Status:      status,
				HostIgnored: ignoreIdx.HostIgnored(snap.TargetID),
			})
		}
		return resp, nil
	}

	baselineInstance := reportstore.GucInstanceKey(base.TargetID)

	for _, snap := range deduped {
		if len(memberFilter) > 0 {
			inst := reportstore.GucInstanceKey(snap.TargetID)
			if !memberFilter[snap.TargetID] && !memberFilter[inst] {
				continue
			}
		} else if q.GroupID != "" {
			continue
		}
		if filterTarget != "" {
			inst := reportstore.GucInstanceKey(snap.TargetID)
			if snap.TargetID != filterTarget && inst != filterInstance && inst != filterTarget {
				continue
			}
		}

		resp.Stats.HostsCompared++
		live, _, _, err := s.Repo.GetServerGucSnapshot(ctx, snap.TargetID)
		if err != nil {
			return nil, err
		}
		host := gucSnapshotHostLabel(snap)
		if len(live) == 0 {
			resp.HostSummaries = append(resp.HostSummaries, GucDriftHostSummary{
				Host:        host,
				TargetID:    snap.TargetID,
				Status:      "no_snapshot",
				HostIgnored: ignoreIdx.HostIgnored(snap.TargetID),
			})
			continue
		}

		// Reference host is the baseline — always matched.
		if base.Source == reportstore.GucBaselineSourceHost &&
			(snap.TargetID == base.TargetID ||
				(baselineInstance != "" && reportstore.GucInstanceKey(snap.TargetID) == baselineInstance)) {
			summary := GucDriftHostSummary{
				Host:        host,
				TargetID:    snap.TargetID,
				Status:      "baseline",
				HostIgnored: ignoreIdx.HostIgnored(snap.TargetID),
			}
			if summary.HostIgnored {
				summary.Status = "ignored"
				resp.Stats.IgnoredServers++
			} else {
				resp.Stats.MatchedServers++
			}
			resp.HostSummaries = append(resp.HostSummaries, summary)
			continue
		}

		if ignoreIdx.HostIgnored(snap.TargetID) {
			resp.HostSummaries = append(resp.HostSummaries, GucDriftHostSummary{
				Host:        host,
				TargetID:    snap.TargetID,
				Status:      "ignored",
				HostIgnored: true,
			})
			resp.Stats.IgnoredServers++
			continue
		}

		rows := postgresconfig.CompareAgainstBaseline(base.Settings, live)
		summary := GucDriftHostSummary{
			Host:          host,
			TargetID:      snap.TargetID,
			Status:        "matched",
			PostgresMajor: postgresconfig.ResolveGucMajor(live),
		}
		for _, row := range rows {
			ignored := ignoreIdx.GucIgnored(snap.TargetID, row.GUC)
			switch row.Status {
			case postgresconfig.DriftDiff, postgresconfig.DriftMissing,
				postgresconfig.DriftVersionUpdated, postgresconfig.DriftVersionNew, postgresconfig.DriftVersionRemoved:
				driftRow := GucDriftRow{
					Host:     host,
					TargetID: snap.TargetID,
					Guc:      row.GUC,
					Live:     row.Live,
					Baseline: row.Baseline,
					Status:   string(row.Status),
					Ignored:  ignored,
				}
				resp.Rows = append(resp.Rows, driftRow)
				if ignored {
					summary.IgnoredCount++
					resp.Stats.TotalIgnored++
					continue
				}
				switch row.Status {
				case postgresconfig.DriftDiff:
					summary.DriftCount++
					resp.Stats.TotalDrifted++
				case postgresconfig.DriftMissing:
					summary.MissingCount++
					resp.Stats.TotalMissing++
				case postgresconfig.DriftVersionUpdated:
					summary.VersionUpdatedCount++
					resp.Stats.TotalVersionUpdated++
				case postgresconfig.DriftVersionNew:
					summary.VersionNewCount++
					resp.Stats.TotalVersionNew++
				case postgresconfig.DriftVersionRemoved:
					summary.VersionRemovedCount++
					resp.Stats.TotalVersionRemoved++
				}
			}
		}
		if summary.DriftCount == 0 && summary.MissingCount == 0 {
			summary.Status = "matched"
			resp.Stats.MatchedServers++
		} else {
			if summary.DriftCount > 0 {
				summary.Status = "drifted"
				resp.Stats.DriftingServers++
			} else {
				summary.Status = "missing"
			}
			if summary.MissingCount > 0 {
				resp.Stats.MissingServers++
			}
		}
		resp.HostSummaries = append(resp.HostSummaries, summary)
	}
	return resp, nil
}

// dedupeGucSnapshotsByInstance keeps one snapshot per Postgres instance (host:port).
// Older rows were stored per database (postgres:host:port:db), which duplicated GUC drift.
func dedupeGucSnapshotsByInstance(snapshots []reportstore.GucSnapshotSummary) []reportstore.GucSnapshotSummary {
	if len(snapshots) <= 1 {
		return snapshots
	}
	best := map[string]reportstore.GucSnapshotSummary{}
	order := make([]string, 0, len(snapshots))
	for _, snap := range snapshots {
		key := reportstore.GucInstanceKey(snap.TargetID)
		if key == "" {
			key = snap.TargetID
		}
		prev, ok := best[key]
		if !ok {
			best[key] = snap
			order = append(order, key)
			continue
		}
		if snap.CollectedAt > prev.CollectedAt {
			best[key] = snap
		}
	}
	out := make([]reportstore.GucSnapshotSummary, 0, len(order))
	for _, key := range order {
		out = append(out, best[key])
	}
	return out
}

func hostGucDriftCount(ctx context.Context, s *Service, targetID string) string {
	if s == nil || s.Repo == nil || targetID == "" {
		return "-"
	}
	base, err := s.resolveEffectiveGucBaseline(ctx)
	if err != nil || postgresconfig.CountGucSettings(base.Settings) == 0 {
		return "-"
	}
	if base.Source == reportstore.GucBaselineSourceHost &&
		(targetID == base.TargetID ||
			reportstore.GucInstanceKey(targetID) == reportstore.GucInstanceKey(base.TargetID)) {
		return "0"
	}
	live, _, _, err := s.Repo.GetServerGucSnapshot(ctx, targetID)
	if err != nil || len(live) == 0 {
		return "-"
	}
	ignoreIdx := reportstore.GucIgnoreIndex{Hosts: map[string]bool{}, Gucs: map[string]map[string]bool{}}
	if ignores, err := s.Repo.ListGucIgnores(ctx); err == nil {
		ignoreIdx = reportstore.BuildGucIgnoreIndex(ignores)
	}
	if ignoreIdx.HostIgnored(targetID) {
		return "0"
	}
	n := 0
	for _, row := range postgresconfig.CompareAgainstBaseline(base.Settings, live) {
		if row.Status == postgresconfig.DriftMatch || postgresconfig.IsVersionExpectedStatus(row.Status) {
			continue
		}
		if ignoreIdx.GucIgnored(targetID, row.GUC) {
			continue
		}
		n++
	}
	if n == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", n)
}

func gucSnapshotHostLabel(s reportstore.GucSnapshotSummary) string {
	host := strings.TrimSpace(s.TargetHost)
	if host == "" {
		return s.TargetID
	}
	return host
}

// GucBaseline returns the stored global baseline (host reference or legacy file settings).
func (s *Service) GucBaseline(ctx context.Context) (*GucBaselineResponse, error) {
	return s.GucBaselineForGroup(ctx, "")
}

// GucBaselineForGroup returns global or group baseline metadata.
func (s *Service) GucBaselineForGroup(ctx context.Context, groupID string) (*GucBaselineResponse, error) {
	if s.Repo == nil {
		return &GucBaselineResponse{Settings: map[string]string{}, Source: "none"}, nil
	}
	base, err := s.resolveGucBaselineForGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	resp := &GucBaselineResponse{
		Label:     base.Label,
		Source:    base.Source,
		TargetID:  base.TargetID,
		Host:      base.Host,
		UpdatedAt: base.Updated,
		KeyCount:  postgresconfig.CountGucSettings(base.Settings),
		Settings:  map[string]string{},
		GroupID:   groupID,
	}
	// Do not dump hundreds of SHOW ALL keys to the UI — only legacy small file baselines.
	if base.Source == reportstore.GucBaselineSourceFile && postgresconfig.CountGucSettings(base.Settings) <= 40 {
		resp.Settings = postgresconfig.UnpackGucSnapshotBundle(base.Settings).Settings
	}
	if resp.Source == "" || resp.Source == "none" {
		if resp.KeyCount == 0 {
			resp.Source = "none"
		}
	}
	return resp, nil
}

// PutGucBaseline upserts a legacy file/JSON settings baseline (API compatibility).
func (s *Service) PutGucBaseline(ctx context.Context, label string, settings map[string]string) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	normalized := postgresconfig.NormalizeGucSettings(reportstore.StripGucBaselineMeta(settings))
	if label == "" {
		label = "global"
	}
	stored := make(map[string]string, len(normalized)+1)
	for k, v := range normalized {
		stored[k] = v
	}
	stored[reportstore.GucBaselineMetaSource] = reportstore.GucBaselineSourceFile
	return s.Repo.UpsertGucBaseline(ctx, label, stored)
}

// PutGucBaselineFromHost sets the golden baseline to a collector host's latest SHOW ALL snapshot.
func (s *Service) PutGucBaselineFromHost(ctx context.Context, targetID string) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return fmt.Errorf("target_id is required")
	}
	settings, host, _, err := s.Repo.GetServerGucSnapshot(ctx, targetID)
	if err != nil {
		return err
	}
	if len(settings) == 0 {
		return fmt.Errorf("no SHOW ALL snapshot for target %s", targetID)
	}
	label := strings.TrimSpace(host)
	if label == "" {
		label = targetID
	}
	return s.Repo.UpsertGucBaseline(ctx, label, reportstore.HostBaselineSettings(targetID))
}

// PutGucGroupBaselineFromHost sets a group's baseline to a host SHOW ALL snapshot.
func (s *Service) PutGucGroupBaselineFromHost(ctx context.Context, groupID, targetID string) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	groupID = strings.TrimSpace(groupID)
	targetID = strings.TrimSpace(targetID)
	if groupID == "" || targetID == "" {
		return fmt.Errorf("group_id and target_id are required")
	}
	settings, _, _, err := s.Repo.GetServerGucSnapshot(ctx, targetID)
	if err != nil {
		return err
	}
	if len(settings) == 0 {
		return fmt.Errorf("no SHOW ALL snapshot for target %s", targetID)
	}
	return s.Repo.SetGucServerGroupBaseline(ctx, groupID, reportstore.HostBaselineSettings(targetID))
}

// PutGucGroupBaselineFile sets a group's baseline from conf/JSON settings.
func (s *Service) PutGucGroupBaselineFile(ctx context.Context, groupID, label string, settings map[string]string) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return fmt.Errorf("group_id is required")
	}
	normalized := postgresconfig.NormalizeGucSettings(reportstore.StripGucBaselineMeta(settings))
	stored := make(map[string]string, len(normalized)+1)
	for k, v := range normalized {
		stored[k] = v
	}
	stored[reportstore.GucBaselineMetaSource] = reportstore.GucBaselineSourceFile
	_ = label
	return s.Repo.SetGucServerGroupBaseline(ctx, groupID, stored)
}

// GucSnapshots lists latest SHOW ALL snapshots per server.
func (s *Service) GucSnapshots(ctx context.Context) (*GucSnapshotsResponse, error) {
	if s.Repo == nil {
		return &GucSnapshotsResponse{Snapshots: []GucSnapshotEntry{}}, nil
	}
	list, err := s.Repo.ListServerGucSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	deduped := dedupeGucSnapshotsByInstance(list)
	out := make([]GucSnapshotEntry, 0, len(deduped))
	for _, snap := range deduped {
		out = append(out, GucSnapshotEntry{
			TargetID:    snap.TargetID,
			Host:        gucSnapshotHostLabel(snap),
			NodeID:      snap.NodeID,
			CollectedAt: snap.CollectedAt,
			KeyCount:    snap.KeyCount,
		})
	}
	return &GucSnapshotsResponse{Snapshots: out}, nil
}
