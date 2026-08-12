package postgresconfig

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type GroupedServers struct {
	GroupName string
	Servers   []string
}

type GroupedServersList []GroupedServers

func (g GroupedServersList) FindGroupForServer(serverName string) *GroupedServers {
	for _, group := range g {
		if slices.Contains(group.Servers, serverName) {
			return &group
		}
	}
	return nil
}

// AllConfigValues holds the result of comparing configurations across multiple databases
type AllConfigValues struct {
	AllSettings     []ConfigSetting
	AllUniqueFields []string
}

type ConfigCompareResult struct {
	One2OneComparison *ConfigCompareOne2OneResult
}

type ConfigCompareOne2OneResult struct {
	BaseServer                   string
	One2OneComparisonNotMatching map[string]map[string][]string
	One2OneComparisonMatching    []string
}

// ConfigSetting represents the configuration settings for a single database
type ConfigSetting struct {
	Name   string
	Values map[string]string
}

// CompareConfig compares the configuration settings of multiple PostgreSQL databases
// It takes an array of connection strings and returns a CompareConfigResult
func GetAllConfigValues(connectionStrings []string) (*AllConfigValues, error) {
	if len(connectionStrings) < 2 {
		return nil, fmt.Errorf("at least two connection strings are required for comparison")
	}

	result := &AllConfigValues{
		AllSettings:     make([]ConfigSetting, 0),
		AllUniqueFields: make([]string, 0),
	}

	uniqueFields := make(map[string]bool)
	// Iterate through each connection string and fetch configuration values
	for _, connectionString := range connectionStrings {
		configValues, err := GetAllConfigValuesFromConnectionString(connectionString)
		if err != nil {
			return nil, fmt.Errorf("error getting config values: %v", err)
		}

		// Add the configuration settings for this database to the result
		result.AllSettings = append(result.AllSettings, ConfigSetting{
			Name:   connectionString,
			Values: configValues,
		})

		// Keep track of all unique configuration fields across all databases
		for field := range configValues {
			uniqueFields[field] = true
		}
	}

	for field := range uniqueFields {
		result.AllUniqueFields = append(result.AllUniqueFields, field)
	}

	return result, nil
}

// DriftStatus classifies a baseline key comparison result.
type DriftStatus string

const (
	DriftMatch   DriftStatus = "match"
	DriftDiff    DriftStatus = "drift"
	DriftMissing DriftStatus = "missing"
)

// BaselineCompareRow is one baseline key compared against live SHOW ALL / pg_settings data.
// When baseline and live majors differ (15–18), Status may also be version_updated,
// version_removed, or version_new (see guc_version.go).
type BaselineCompareRow struct {
	GUC      string
	Baseline string
	Live     string
	Status   DriftStatus
}

// GetAllConfigValuesFromConnectionString fetches all configuration values from a single PostgreSQL database
func GetAllConfigValuesFromConnectionString(connectionString string) (map[string]string, error) {
	db, err := postgresdb.ConnectDatabaseUsingConnectionString(connectionString, true)
	if err != nil {
		return nil, fmt.Errorf("error opening postgres connection: %v", err)
	}
	defer db.Close()

	configValues, err := utils.GetConfigValueFromPostgres(db)
	if err != nil {
		return nil, fmt.Errorf("error getting config values: %v", err)
	}

	return configValues, nil
}

// NormalizeGucName lowercases a GUC / conf key for stable comparison.
// SHOW ALL uses mixed case for some names (DateStyle, TimeZone); postgresql.conf is usually lowercase.
func NormalizeGucName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// IsConfOnlyDirective reports postgresql.conf directives that are not runtime GUCs
// (never appear in SHOW ALL / pg_settings).
func IsConfOnlyDirective(name string) bool {
	switch NormalizeGucName(name) {
	case "include", "include_dir", "include_if_exists":
		return true
	default:
		return false
	}
}

// NormalizeGucSettings returns a copy with lowercased keys and conf-only directives removed.
// Preserves pg_settings unit/vartype meta keys used for drift comparison.
func NormalizeGucSettings(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := NormalizeGucName(k)
		if key == "" || IsConfOnlyDirective(key) {
			continue
		}
		if strings.HasPrefix(key, "__kshield_") {
			switch key {
			case GucMetaUnitsJSON, GucMetaVartypesJSON, GucMetaSourceQuery:
				out[key] = v
			}
			continue
		}
		out[key] = v
	}
	return out
}

// NormalizeGucValue trims and normalizes PostgreSQL GUC values for comparison.
func NormalizeGucValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	lower := strings.ToLower(v)
	switch lower {
	case "on", "yes", "true", "1":
		return "on"
	case "off", "no", "false", "0":
		return "off"
	default:
		return lower
	}
}

// gucValuesEqual reports whether two GUC values are equivalent after normalization.
// Boolean aliases match; memory/time units are compared in base units (bytes / ms)
// so values like 8MB, 8192kB, and 8388608 are treated as equal (pg_settings-style).
func gucValuesEqual(a, b string) bool {
	na := NormalizeGucValue(a)
	nb := NormalizeGucValue(b)
	if strings.EqualFold(na, nb) {
		return true
	}
	if bytesA, okA := parsePostgresMemoryBytes(a); okA {
		if bytesB, okB := parsePostgresMemoryBytes(b); okB && bytesA == bytesB {
			return true
		}
	}
	if msA, okA := parsePostgresDurationMs(a); okA {
		if msB, okB := parsePostgresDurationMs(b); okB && msA == msB {
			return true
		}
	}
	return false
}

// parsePostgresMemoryBytes converts SHOW / conf memory strings to bytes.
// Accepts bare integers (treated as bytes) and unit suffixes B, kB, MB, GB, TB.
func parsePostgresMemoryBytes(v string) (int64, bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return 0, false
	}
	// Strip optional surrounding quotes.
	if len(v) >= 2 && ((v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"')) {
		v = v[1 : len(v)-1]
	}
	numEnd := 0
	for numEnd < len(v) {
		c := v[numEnd]
		if (c >= '0' && c <= '9') || c == '.' {
			numEnd++
			continue
		}
		break
	}
	if numEnd == 0 {
		return 0, false
	}
	numStr := v[:numEnd]
	unit := strings.TrimSpace(v[numEnd:])
	var n float64
	if _, err := fmt.Sscanf(numStr, "%f", &n); err != nil {
		return 0, false
	}
	var mult float64
	switch unit {
	case "", "b":
		mult = 1
	case "kb", "k":
		mult = 1024
	case "mb", "m":
		mult = 1024 * 1024
	case "gb", "g":
		mult = 1024 * 1024 * 1024
	case "tb", "t":
		mult = 1024 * 1024 * 1024 * 1024
	default:
		return 0, false
	}
	return int64(n * mult), true
}

// parsePostgresDurationMs converts SHOW / conf time strings to milliseconds.
// Accepts bare integers (treated as ms) and us, ms, s, min, h, d.
func parsePostgresDurationMs(v string) (int64, bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return 0, false
	}
	if len(v) >= 2 && ((v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"')) {
		v = v[1 : len(v)-1]
	}
	numEnd := 0
	for numEnd < len(v) {
		c := v[numEnd]
		if (c >= '0' && c <= '9') || c == '.' {
			numEnd++
			continue
		}
		break
	}
	if numEnd == 0 {
		return 0, false
	}
	numStr := v[:numEnd]
	unit := strings.TrimSpace(v[numEnd:])
	var n float64
	if _, err := fmt.Sscanf(numStr, "%f", &n); err != nil {
		return 0, false
	}
	var mult float64
	switch unit {
	case "", "ms":
		mult = 1
	case "us":
		mult = 0.001
	case "s":
		mult = 1000
	case "min":
		mult = 60 * 1000
	case "h":
		mult = 60 * 60 * 1000
	case "d":
		mult = 24 * 60 * 60 * 1000
	default:
		return 0, false
	}
	return int64(n * mult), true
}

// liveByNormalizedKey indexes live SHOW ALL / pg_settings values by lowercase GUC name.
func liveByNormalizedKey(live map[string]string) map[string]string {
	out := make(map[string]string, len(live))
	for k, v := range live {
		key := NormalizeGucName(k)
		if key == "" || strings.HasPrefix(key, "__kshield_") {
			continue
		}
		if _, exists := out[key]; !exists {
			out[key] = v
		}
	}
	return out
}

// CompareAgainstBaseline compares only keys present in baseline.
// Keys are matched case-insensitively. Conf-only directives are skipped.
// Missing live keys are reported as DriftMissing.
// When snapshots include pg_settings unit metadata, values are compared in base units
// (bytes / ms) so 8MB, 8192kB, and 8388608 match.
// When both sides resolve to different majors in 15–18, expected version changes are
// reclassified as version_updated / version_removed and catalog "new" live-only GUCs
// are appended as version_new. Same-major compares are unchanged.
func CompareAgainstBaseline(baseline, live map[string]string) []BaselineCompareRow {
	if len(baseline) == 0 {
		return nil
	}
	baseBundle := UnpackGucSnapshotBundle(baseline)
	liveBundle := UnpackGucSnapshotBundle(live)
	liveIndex := liveByNormalizedKey(liveBundle.Settings)

	keys := make([]string, 0, len(baseBundle.Settings))
	for k := range baseBundle.Settings {
		if IsConfOnlyDirective(k) || strings.HasPrefix(k, "__kshield_") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]BaselineCompareRow, 0, len(keys))
	for _, guc := range keys {
		expected := baseBundle.Settings[guc]
		canon := NormalizeGucName(guc)
		liveVal, ok := liveIndex[canon]
		unitB := baseBundle.Units[canon]
		unitL := liveBundle.Units[canon]
		row := BaselineCompareRow{
			GUC:      canon,
			Baseline: FormatGucDisplay(expected, unitB),
			Live:     FormatGucDisplay(liveVal, unitL),
		}
		if !ok {
			row.Status = DriftMissing
			row.Live = "-"
		} else if gucValuesEqualWithUnits(expected, unitB, liveVal, unitL) {
			row.Status = DriftMatch
		} else {
			row.Status = DriftDiff
		}
		out = append(out, row)
	}

	from := ResolveGucMajor(baseline)
	to := ResolveGucMajor(live)
	if from > 0 && to > 0 && from != to {
		out = applyVersionClassification(out, baseline, live, from, to)
	}
	return out
}

// DifferentConfigValue represents a configuration value that differs across databases
type DifferentConfigValue struct {
	Field  string
	Values map[string][]string
}

// NewDifferentConfigValue creates a new DifferentConfigValue instance
func NewDifferentConfigValue(field string) *DifferentConfigValue {
	return &DifferentConfigValue{
		Field:  field,
		Values: make(map[string][]string),
	}
}

// CompareAllServersWithBase compares all the servers with base server provided by user
// from *postgresconfig.AllConfigValues.AllSettings consider first as base and compare all
// other servers with this base server
func CompareAllServersWithBase(allConfigValues *AllConfigValues) *ConfigCompareOne2OneResult {
	if len(allConfigValues.AllSettings) < 2 {
		return nil
	}

	result := &ConfigCompareOne2OneResult{
		BaseServer:                   allConfigValues.AllSettings[0].Name,
		One2OneComparisonNotMatching: make(map[string]map[string][]string),
		One2OneComparisonMatching:    make([]string, 0),
	}

	baseSettings := allConfigValues.AllSettings[0]
	for i := 1; i < len(allConfigValues.AllSettings); i++ {
		compareSettings := allConfigValues.AllSettings[i]
		m := make(map[string][]string)
		for _, field := range allConfigValues.AllUniqueFields {
			if baseSettings.Values[field] != compareSettings.Values[field] {
				m[field] = []string{baseSettings.Values[field], compareSettings.Values[field]}
			}
		}

		if len(m) > 0 {
			result.One2OneComparisonNotMatching[compareSettings.Name] = m
		} else {
			result.One2OneComparisonMatching = append(result.One2OneComparisonMatching, compareSettings.Name)
		}
	}

	return result
}
