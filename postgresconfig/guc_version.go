package postgresconfig

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// GucMetaPgVersion is the raw server_version string packed into snapshots.
	GucMetaPgVersion = "__kshield_pg_version"
	// GucMetaPgMajor is the parsed major version (e.g. "16") packed into snapshots.
	GucMetaPgMajor = "__kshield_pg_major"
)

// Extra drift statuses for cross-major expected changes.
const (
	DriftVersionUpdated DriftStatus = "version_updated"
	DriftVersionNew     DriftStatus = "version_new"
	DriftVersionRemoved DriftStatus = "version_removed"
)

// GucVersionDiff is the composed new/removed/updated set between two majors.
type GucVersionDiff struct {
	From    int
	To      int
	New     map[string]struct{}
	Removed map[string]struct{}
	Updated map[string]struct{}
}

var pgMajorFromVersionRe = regexp.MustCompile(`(?i)^(?:PostgreSQL\s+)?(\d+)`)

// ParsePostgresMajor extracts the major version from strings like "16.4", "PostgreSQL 18.1".
// Returns 0 when unrecognized.
func ParsePostgresMajor(version string) int {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0
	}
	m := pgMajorFromVersionRe.FindStringSubmatch(version)
	if len(m) < 2 {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 10 || n > 99 {
		return 0
	}
	return n
}

// ResolveGucMajor returns the major for a packed snapshot: meta key first, then inference.
func ResolveGucMajor(settings map[string]string) int {
	if len(settings) == 0 {
		return 0
	}
	if v, ok := settings[GucMetaPgMajor]; ok {
		if n := ParsePostgresMajor(v); n > 0 {
			return n
		}
	}
	if v, ok := settings[GucMetaPgVersion]; ok {
		if n := ParsePostgresMajor(v); n > 0 {
			return n
		}
	}
	return InferGucMajorFromSettings(settings)
}

// InferGucMajorFromSettings guesses major from presence of version-specific GUCs (15–18).
// Returns 0 when ambiguous or outside the catalog range.
func InferGucMajorFromSettings(settings map[string]string) int {
	bundle := UnpackGucSnapshotBundle(settings)
	has := func(name string) bool {
		_, ok := bundle.Settings[NormalizeGucName(name)]
		return ok
	}

	lo, hi := 15, 18

	// Lower bounds from parameters introduced at a major.
	introductions := []struct {
		major int
		name  string
	}{
		{16, "vacuum_buffer_usage_limit"},
		{16, "scram_iterations"},
		{16, "debug_parallel_query"},
		{17, "allow_alter_system"},
		{17, "io_combine_limit"},
		{17, "summarize_wal"},
		{18, "io_method"},
		{18, "ssl_groups"},
		{18, "autovacuum_worker_slots"},
	}
	for _, m := range introductions {
		if has(m.name) && m.major > lo {
			lo = m.major
		}
	}

	// Upper bounds from parameters removed after lastMajor (still present ⇒ ≤ lastMajor).
	removals := []struct {
		lastMajor int
		name      string
	}{
		{15, "force_parallel_mode"},
		{15, "promote_trigger_file"},
		{15, "vacuum_defer_cleanup_age"},
		{16, "db_user_namespace"},
		{16, "old_snapshot_threshold"},
		{16, "trace_recovery_messages"},
		{17, "ssl_ecdh_curve"},
	}
	for _, m := range removals {
		if has(m.name) && m.lastMajor < hi {
			hi = m.lastMajor
		}
	}

	if lo > hi {
		return 0
	}
	// Prefer the tightest lower-bound signal when still a range (modern servers).
	if lo == hi {
		return lo
	}
	// No strong introduction markers and no removal markers → unknown.
	if lo == 15 && hi == 18 && !has("vacuum_buffer_usage_limit") && !has("force_parallel_mode") {
		return 0
	}
	return lo
}

// ComposeGucVersionDiff builds New/Removed/Updated for any from→to pair in 15–18.
// Downgrades swap New/Removed; Updated is symmetric (param changed somewhere on the path).
func ComposeGucVersionDiff(from, to int) GucVersionDiff {
	out := GucVersionDiff{
		From:    from,
		To:      to,
		New:     map[string]struct{}{},
		Removed: map[string]struct{}{},
		Updated: map[string]struct{}{},
	}
	if from == 0 || to == 0 || from == to {
		return out
	}
	if !supportedMajor(from) || !supportedMajor(to) {
		return out
	}

	ascending := from < to
	start, end := from, to
	if !ascending {
		start, end = to, from
	}

	for _, hop := range gucVersionHops {
		if hop.From < start || hop.To > end {
			continue
		}
		// hop fully inside (start, end]
		if hop.From >= start && hop.To <= end {
			for _, n := range hop.New {
				out.New[NormalizeGucName(n)] = struct{}{}
			}
			for _, n := range hop.Removed {
				out.Removed[NormalizeGucName(n)] = struct{}{}
			}
			for _, n := range hop.Updated {
				out.Updated[NormalizeGucName(n)] = struct{}{}
			}
		}
	}

	if !ascending {
		out.New, out.Removed = out.Removed, out.New
	}
	return out
}

func supportedMajor(m int) bool {
	for _, v := range SupportedGucMajorVersions {
		if v == m {
			return true
		}
	}
	return false
}

// IsVersionExpectedStatus reports whether a diff is an expected cross-major catalog change.
func IsVersionExpectedStatus(s DriftStatus) bool {
	switch s {
	case DriftVersionUpdated, DriftVersionNew, DriftVersionRemoved:
		return true
	default:
		return false
	}
}

// applyVersionClassification rewrites drift/missing rows using the version catalog and
// appends version_new rows for live-only parameters introduced between majors.
func applyVersionClassification(rows []BaselineCompareRow, baseline, live map[string]string, from, to int) []BaselineCompareRow {
	diff := ComposeGucVersionDiff(from, to)
	if len(diff.New) == 0 && len(diff.Removed) == 0 && len(diff.Updated) == 0 {
		return rows
	}

	baseBundle := UnpackGucSnapshotBundle(baseline)
	liveBundle := UnpackGucSnapshotBundle(live)
	liveIndex := liveByNormalizedKey(liveBundle.Settings)

	out := make([]BaselineCompareRow, 0, len(rows)+len(diff.New))
	seen := map[string]struct{}{}
	for _, row := range rows {
		canon := NormalizeGucName(row.GUC)
		seen[canon] = struct{}{}
		switch row.Status {
		case DriftMissing:
			if _, ok := diff.Removed[canon]; ok {
				row.Status = DriftVersionRemoved
			}
		case DriftDiff:
			if _, ok := diff.Updated[canon]; ok {
				row.Status = DriftVersionUpdated
			}
		}
		out = append(out, row)
	}

	// Live-only params that are catalog "new" for this upgrade (or "removed" on downgrade path → already in New after swap).
	newNames := make([]string, 0, len(diff.New))
	for name := range diff.New {
		newNames = append(newNames, name)
	}
	sort.Strings(newNames)
	for _, name := range newNames {
		if _, ok := seen[name]; ok {
			continue
		}
		if _, inBase := baseBundle.Settings[name]; inBase {
			continue
		}
		liveVal, ok := liveIndex[name]
		if !ok {
			continue
		}
		out = append(out, BaselineCompareRow{
			GUC:      name,
			Baseline: "-",
			Live:     FormatGucDisplay(liveVal, liveBundle.Units[name]),
			Status:   DriftVersionNew,
		})
	}
	return out
}
