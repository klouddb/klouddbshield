package service

import (
	"context"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/repository"
	"github.com/klouddb/klouddbshield/postgresconfig"
)

type complianceSnapshot struct {
	Drift          []StrategicDrift
	DriftLabels    []string
	Audit          [][]string
	Heatmap        [][]int
	HeatmapColumns []string
	PiiScanned     bool
}

func buildComplianceSnapshot(ctx context.Context, s *Service, runs []*reportstore.RunRow, since time.Time, rangeKey string) complianceSnapshot {
	snap := complianceSnapshot{
		Drift:       []StrategicDrift{},
		DriftLabels: []string{},
		Audit:       buildCriticalAuditList(runs),
	}
	snap.Drift, snap.DriftLabels = buildConfigDriftSeries(ctx, s, since, runs, rangeKey)
	snap.HeatmapColumns, snap.Heatmap, snap.PiiScanned = buildPIIHeatmap(ctx, s.Repo, runs)
	return snap
}

func buildCriticalAuditList(runs []*reportstore.RunRow) [][]string {
	var audit [][]string
	for _, run := range runs {
		host := hostLabel(run)
		for _, r := range decodeCISResults(run.Report) {
			if !strings.EqualFold(r.Status, "Fail") {
				continue
			}
			if !isConfigAuditControl(r) {
				continue
			}
			audit = append(audit, []string{auditCheckLabel(r), host})
			if len(audit) >= 8 {
				return audit
			}
		}
	}
	return audit
}

func auditCheckLabel(r model.Result) string {
	if fr := strings.TrimSpace(r.FailReason); fr != "" {
		return fr
	}
	if t := strings.TrimSpace(r.Title); t != "" {
		return trimForTable(t, 48)
	}
	return r.Control
}

// configAuditCheckLabel is shown in fleet Config Audit rows (control + title).
func configAuditCheckLabel(r model.Result) string {
	ctrl := strings.TrimSpace(r.Control)
	title := trimForTable(strings.TrimSpace(r.Title), 52)
	if ctrl != "" && title != "" {
		return ctrl + " — " + title
	}
	if title != "" {
		return title
	}
	return ctrl
}

func cisResultStatus(r model.Result) string {
	switch strings.ToLower(strings.TrimSpace(r.Status)) {
	case "pass":
		return "Pass"
	case "fail":
		return "Fail"
	case "manual":
		return "Manual"
	case "":
		return "Unknown"
	default:
		return strings.TrimSpace(r.Status)
	}
}

func configAuditAction(status string) string {
	switch strings.ToLower(status) {
	case "pass":
		return "View"
	case "manual":
		return "Review"
	default:
		return "Open"
	}
}

func isConfigAuditControl(r model.Result) bool {
	ctrl := strings.TrimSpace(r.Control)
	if strings.HasPrefix(ctrl, "3.") || strings.HasPrefix(ctrl, "4.") ||
		strings.HasPrefix(ctrl, "5.") || strings.HasPrefix(ctrl, "6.") {
		return true
	}
	return cisMatchesAny(r,
		"guc", "config", "shared_", "log_", "logging", "syslog", "wal_", "fsync",
		"preload", "pgaudit", "audit", "debug_print", "rotation", "destination",
	)
}

func buildConfigDriftSeries(ctx context.Context, s *Service, _ time.Time, latestRuns []*reportstore.RunRow, _ string) ([]StrategicDrift, []string) {
	if drift, labels := buildGucDriftStrategicChart(ctx, s); driftHasValues(drift) {
		return drift, labels
	}
	return buildConfigDriftPerHost(latestRuns)
}

func driftHasValues(drift []StrategicDrift) bool {
	for _, d := range drift {
		if d.B > 0 || d.D > 0 {
			return true
		}
	}
	return false
}

// buildGucDriftStrategicChart shows matched vs drifted GUC settings per host (links to GUC drift page).
func buildGucDriftStrategicChart(ctx context.Context, s *Service) ([]StrategicDrift, []string) {
	if s == nil || s.Repo == nil {
		return nil, nil
	}
	base, err := s.resolveEffectiveGucBaseline(ctx)
	if err != nil || len(base.Settings) == 0 {
		return nil, nil
	}
	baseline := base.Settings
	snapshots, err := s.Repo.ListServerGucSnapshots(ctx)
	if err != nil || len(snapshots) == 0 {
		return nil, nil
	}

	ignoreIdx := reportstore.GucIgnoreIndex{Hosts: map[string]bool{}, Gucs: map[string]map[string]bool{}}
	if ignores, err := s.Repo.ListGucIgnores(ctx); err == nil {
		ignoreIdx = reportstore.BuildGucIgnoreIndex(ignores)
	}

	drift := make([]StrategicDrift, 0, len(snapshots))
	labels := make([]string, 0, len(snapshots))
	for _, snap := range dedupeGucSnapshotsByInstance(snapshots) {
		if base.Source == "host" &&
			(snap.TargetID == base.TargetID ||
				reportstore.GucInstanceKey(snap.TargetID) == reportstore.GucInstanceKey(base.TargetID)) {
			continue
		}
		if ignoreIdx.HostIgnored(snap.TargetID) {
			continue
		}
		live, _, _, err := s.Repo.GetServerGucSnapshot(ctx, snap.TargetID)
		if err != nil || len(live) == 0 {
			continue
		}
		matched, deviated := 0, 0
		for _, row := range postgresconfig.CompareAgainstBaseline(baseline, live) {
			if row.Status == postgresconfig.DriftMatch || postgresconfig.IsVersionExpectedStatus(row.Status) {
				matched++
				continue
			}
			if ignoreIdx.GucIgnored(snap.TargetID, row.GUC) {
				matched++ // ignored findings count as non-drift for fleet KPI consistency
				continue
			}
			deviated++
		}
		if matched+deviated == 0 {
			continue
		}
		drift = append(drift, StrategicDrift{B: matched, D: deviated})
		labels = append(labels, gucSnapshotHostLabel(snap))
	}
	return drift, labels
}

// buildConfigDriftPerHost falls back to CIS config-audit pass/fail counts per latest host run.
func buildConfigDriftPerHost(runs []*reportstore.RunRow) ([]StrategicDrift, []string) {
	if len(runs) == 0 {
		return nil, nil
	}
	drift := make([]StrategicDrift, 0, len(runs))
	labels := make([]string, 0, len(runs))
	for _, run := range runs {
		pass, fail := configAuditPassFail(run.Report)
		if pass+fail == 0 {
			continue
		}
		drift = append(drift, StrategicDrift{B: pass, D: fail})
		labels = append(labels, hostLabel(run))
	}
	if len(drift) == 0 {
		return nil, nil
	}
	return drift, labels
}

func configAuditPassFail(report map[string]interface{}) (pass, fail int) {
	for _, r := range decodeCISResults(report) {
		if !isConfigAuditControl(r) {
			continue
		}
		if strings.EqualFold(r.Status, "Fail") {
			fail++
		} else if strings.EqualFold(r.Status, "Pass") {
			pass++
		}
	}
	return pass, fail
}

// buildPIIHeatmap aggregates PII findings into severity rows × host columns.
func buildPIIHeatmap(ctx context.Context, repo repository.Repository, runs []*reportstore.RunRow) (columns []string, grid [][]int, scanned bool) {
	const maxHosts = 8
	hostIndex := map[string]int{}

	for _, run := range runs {
		data, meta := decodePIIResults(resolvePIIReport(ctx, repo, run))
		if len(data) == 0 && len(meta) == 0 {
			continue
		}
		scanned = true
		host := hostLabel(run)
		if _, ok := hostIndex[host]; !ok {
			if len(columns) >= maxHosts {
				continue
			}
			hostIndex[host] = len(columns)
			columns = append(columns, host)
		}
		col := hostIndex[host]
		if col < 0 || col >= len(columns) {
			continue
		}
		if grid == nil {
			grid = zeroHeatmapGrid(len(columns))
		}
		for _, pr := range append(data, meta...) {
			sev := piiSeverityRow(pr)
			if sev >= 0 && sev < len(grid) && col < len(grid[sev]) {
				grid[sev][col]++
			}
		}
	}
	if !scanned {
		return nil, nil, false
	}
	if len(columns) == 0 {
		return nil, zeroHeatmapGrid(0), true
	}
	return columns, grid, true
}

func zeroHeatmapGrid(cols int) [][]int {
	if cols < 1 {
		cols = 1
	}
	return [][]int{
		make([]int, cols),
		make([]int, cols),
		make([]int, cols),
		make([]int, cols),
	}
}

func piiSeverityRow(pr PiiScannerRow) int {
	blob := strings.ToLower(strings.TrimSpace(pr.Confidence + " " + pr.Label + " " + pr.Matched))
	switch {
	case strings.Contains(blob, "high"):
		return 0
	case strings.Contains(blob, "moderate") || strings.Contains(blob, "medium"):
		return 1
	case strings.Contains(blob, "desirable"):
		return 2
	case strings.Contains(blob, "low"):
		return 3
	default:
		return 2
	}
}
