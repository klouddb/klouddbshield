package postgresconfig

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// Reserved keys packed into snapshot settings_json alongside GUC values.
const (
	GucMetaUnitsJSON        = "__kshield_units_json"
	GucMetaVartypesJSON     = "__kshield_vartypes_json"
	GucMetaSourceQuery      = "__kshield_source_query"
	GucMetaSourcePgSettings = "pg_settings"
)

// GucSnapshotBundle is settings plus optional pg_settings unit/vartype metadata.
type GucSnapshotBundle struct {
	Settings  map[string]string
	Units     map[string]string
	Vartypes  map[string]string
	PgVersion string // raw SHOW server_version
	PgMajor   int    // parsed major when known
}

// PackGucSnapshotBundle embeds unit/vartype maps into a flat settings map for storage.
func PackGucSnapshotBundle(b GucSnapshotBundle) map[string]string {
	out := make(map[string]string, len(b.Settings)+5)
	for k, v := range b.Settings {
		if strings.HasPrefix(k, "__kshield_") {
			continue
		}
		out[NormalizeGucName(k)] = v
	}
	if len(b.Units) > 0 {
		if blob, err := json.Marshal(normalizeStringMap(b.Units)); err == nil {
			out[GucMetaUnitsJSON] = string(blob)
		}
	}
	if len(b.Vartypes) > 0 {
		if blob, err := json.Marshal(normalizeStringMap(b.Vartypes)); err == nil {
			out[GucMetaVartypesJSON] = string(blob)
		}
	}
	if v := strings.TrimSpace(b.PgVersion); v != "" {
		out[GucMetaPgVersion] = v
		if b.PgMajor <= 0 {
			b.PgMajor = ParsePostgresMajor(v)
		}
	}
	if b.PgMajor > 0 {
		out[GucMetaPgMajor] = strconv.Itoa(b.PgMajor)
	}
	out[GucMetaSourceQuery] = GucMetaSourcePgSettings
	return out
}

// UnpackGucSnapshotBundle extracts settings and pg_settings metadata from a stored map.
func UnpackGucSnapshotBundle(in map[string]string) GucSnapshotBundle {
	out := GucSnapshotBundle{
		Settings: map[string]string{},
		Units:    map[string]string{},
		Vartypes: map[string]string{},
	}
	if len(in) == 0 {
		return out
	}
	for k, v := range in {
		switch k {
		case GucMetaUnitsJSON:
			_ = json.Unmarshal([]byte(v), &out.Units)
		case GucMetaVartypesJSON:
			_ = json.Unmarshal([]byte(v), &out.Vartypes)
		case GucMetaPgVersion:
			out.PgVersion = strings.TrimSpace(v)
		case GucMetaPgMajor:
			out.PgMajor = ParsePostgresMajor(v)
		case GucMetaSourceQuery, "__kshield_source", "__kshield_target_id":
			continue
		default:
			if strings.HasPrefix(k, "__kshield_") {
				continue
			}
			out.Settings[NormalizeGucName(k)] = v
		}
	}
	out.Units = normalizeStringMap(out.Units)
	out.Vartypes = normalizeStringMap(out.Vartypes)
	if out.PgMajor <= 0 && out.PgVersion != "" {
		out.PgMajor = ParsePostgresMajor(out.PgVersion)
	}
	return out
}

func normalizeStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := NormalizeGucName(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	return out
}

// CountGucSettings excludes reserved meta keys.
func CountGucSettings(settings map[string]string) int {
	n := 0
	for k := range settings {
		if strings.HasPrefix(k, "__kshield_") {
			continue
		}
		n++
	}
	return n
}

// GetPgSettingsBundleFromConnectionString loads name/setting/unit/vartype from pg_settings.
func GetPgSettingsBundleFromConnectionString(connectionString string) (GucSnapshotBundle, error) {
	db, err := postgresdb.ConnectDatabaseUsingConnectionString(connectionString, true)
	if err != nil {
		return GucSnapshotBundle{}, fmt.Errorf("error opening postgres connection: %v", err)
	}
	defer db.Close()
	return GetPgSettingsBundle(db)
}

// GetPgSettingsBundle queries pg_settings for drift collection (not SHOW ALL).
func GetPgSettingsBundle(db *sql.DB) (GucSnapshotBundle, error) {
	rows, err := db.Query(`SELECT name, setting, COALESCE(unit, ''), vartype FROM pg_settings`)
	if err != nil {
		return GucSnapshotBundle{}, fmt.Errorf("error querying pg_settings: %w", err)
	}
	defer rows.Close()

	out := GucSnapshotBundle{
		Settings: map[string]string{},
		Units:    map[string]string{},
		Vartypes: map[string]string{},
	}
	for rows.Next() {
		var name, setting, unit, vartype string
		if err := rows.Scan(&name, &setting, &unit, &vartype); err != nil {
			return GucSnapshotBundle{}, err
		}
		key := NormalizeGucName(name)
		if key == "" || IsConfOnlyDirective(key) {
			continue
		}
		out.Settings[key] = setting
		if u := strings.TrimSpace(unit); u != "" {
			out.Units[key] = u
		}
		if vt := strings.TrimSpace(vartype); vt != "" {
			out.Vartypes[key] = vt
		}
	}
	if err := rows.Err(); err != nil {
		return GucSnapshotBundle{}, err
	}
	if len(out.Settings) == 0 {
		return GucSnapshotBundle{}, fmt.Errorf("no rows from pg_settings")
	}
	var serverVersion string
	if err := db.QueryRow(`SHOW server_version`).Scan(&serverVersion); err == nil {
		out.PgVersion = strings.TrimSpace(serverVersion)
		out.PgMajor = ParsePostgresMajor(out.PgVersion)
	}
	return out, nil
}

// gucValuesEqualWithUnits compares using pg_settings setting+unit when available.
// Falls back to string / human-unit parsing for legacy SHOW ALL or conf baselines.
func gucValuesEqualWithUnits(a, unitA, b, unitB string) bool {
	unitA = strings.TrimSpace(unitA)
	unitB = strings.TrimSpace(unitB)

	if unitA != "" || unitB != "" {
		if baseA, okA := pgSettingToBase(a, unitA); okA {
			if baseB, okB := pgSettingToBase(b, unitB); okB && baseA.kind == baseB.kind && baseA.value == baseB.value {
				return true
			}
		}
		// Mixed: one side has pg unit, other is human "8MB" / "5min"
		if unitA != "" {
			if baseA, okA := pgSettingToBase(a, unitA); okA {
				if baseB, okB := humanValueToBase(b, baseA.kind); okB && baseA.value == baseB {
					return true
				}
			}
		}
		if unitB != "" {
			if baseB, okB := pgSettingToBase(b, unitB); okB {
				if baseA, okA := humanValueToBase(a, baseB.kind); okA && baseB.value == baseA {
					return true
				}
			}
		}
	}
	return gucValuesEqual(a, b)
}

type pgBaseKind int

const (
	pgBaseNone pgBaseKind = iota
	pgBaseBytes
	pgBaseMs
)

type pgBaseValue struct {
	kind  pgBaseKind
	value int64
}

// pgSettingToBase converts pg_settings.setting + unit into bytes or milliseconds.
func pgSettingToBase(setting, unit string) (pgBaseValue, bool) {
	setting = strings.TrimSpace(setting)
	unit = strings.TrimSpace(unit)
	if setting == "" {
		return pgBaseValue{}, false
	}
	n, err := strconv.ParseFloat(setting, 64)
	if err != nil {
		// setting may already include a human unit (legacy)
		if unit == "" {
			if b, ok := parsePostgresMemoryBytes(setting); ok {
				return pgBaseValue{kind: pgBaseBytes, value: b}, true
			}
			if ms, ok := parsePostgresDurationMs(setting); ok {
				return pgBaseValue{kind: pgBaseMs, value: ms}, true
			}
		}
		return pgBaseValue{}, false
	}
	if unit == "" {
		return pgBaseValue{}, false
	}
	u := strings.ToLower(unit)
	// Memory units used by pg_settings.unit
	switch u {
	case "b":
		return pgBaseValue{kind: pgBaseBytes, value: int64(n)}, true
	case "kb":
		return pgBaseValue{kind: pgBaseBytes, value: int64(n * 1024)}, true
	case "8kb":
		return pgBaseValue{kind: pgBaseBytes, value: int64(n * 8 * 1024)}, true
	case "mb":
		return pgBaseValue{kind: pgBaseBytes, value: int64(n * 1024 * 1024)}, true
	case "gb":
		return pgBaseValue{kind: pgBaseBytes, value: int64(n * 1024 * 1024 * 1024)}, true
	case "tb":
		return pgBaseValue{kind: pgBaseBytes, value: int64(n * 1024 * 1024 * 1024 * 1024)}, true
	}
	// Time units
	switch u {
	case "us":
		return pgBaseValue{kind: pgBaseMs, value: int64(n / 1000)}, true
	case "ms":
		return pgBaseValue{kind: pgBaseMs, value: int64(n)}, true
	case "s":
		return pgBaseValue{kind: pgBaseMs, value: int64(n * 1000)}, true
	case "min":
		return pgBaseValue{kind: pgBaseMs, value: int64(n * 60 * 1000)}, true
	case "h":
		return pgBaseValue{kind: pgBaseMs, value: int64(n * 60 * 60 * 1000)}, true
	case "d":
		return pgBaseValue{kind: pgBaseMs, value: int64(n * 24 * 60 * 60 * 1000)}, true
	}
	return pgBaseValue{}, false
}

func humanValueToBase(v string, kind pgBaseKind) (int64, bool) {
	switch kind {
	case pgBaseBytes:
		return parsePostgresMemoryBytes(v)
	case pgBaseMs:
		return parsePostgresDurationMs(v)
	default:
		return 0, false
	}
}

// FormatGucDisplay returns a readable value using pg_settings unit when present.
// pg_settings units may carry a block multiplier (e.g. "8kB"), so setting 16 with
// unit "8kB" is 128kB — never the literal concatenation "168kB".
func FormatGucDisplay(setting, unit string) string {
	setting = strings.TrimSpace(setting)
	unit = strings.TrimSpace(unit)
	if setting == "" || unit == "" {
		return setting
	}
	mult, base, ok := splitUnitMultiplier(unit)
	if !ok || mult <= 1 {
		return setting + unit
	}
	n, err := strconv.ParseFloat(setting, 64)
	if err != nil {
		return setting + unit
	}
	// Negative settings are sentinels (-1 = auto/disabled); unit math is meaningless.
	if n < 0 {
		return setting
	}
	scaled := n * float64(mult)
	if bytes, isBytes := unitToBytes(scaled, base); isBytes {
		return humanByteSize(bytes)
	}
	return trimFloatString(scaled) + base
}

// splitUnitMultiplier parses a pg_settings unit into its multiplier and base unit.
// "8kB" -> (8, "kB"); "kB" -> (1, "kB"); "ms" -> (1, "ms").
func splitUnitMultiplier(unit string) (int64, string, bool) {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return 0, "", false
	}
	i := 0
	for i < len(unit) && unit[i] >= '0' && unit[i] <= '9' {
		i++
	}
	base := unit[i:]
	if base == "" {
		return 0, "", false
	}
	if i == 0 {
		return 1, base, true
	}
	mult, err := strconv.ParseInt(unit[:i], 10, 64)
	if err != nil || mult <= 0 {
		return 0, "", false
	}
	return mult, base, true
}

// unitToBytes converts a value in a memory unit to bytes. Returns false for time units.
func unitToBytes(value float64, base string) (int64, bool) {
	switch strings.ToLower(base) {
	case "b":
		return int64(value), true
	case "kb":
		return int64(value * 1024), true
	case "mb":
		return int64(value * 1024 * 1024), true
	case "gb":
		return int64(value * 1024 * 1024 * 1024), true
	case "tb":
		return int64(value * 1024 * 1024 * 1024 * 1024), true
	}
	return 0, false
}

// humanByteSize renders bytes using the largest unit that divides evenly (131072 -> "128kB").
func humanByteSize(b int64) string {
	if b == 0 {
		return "0B"
	}
	sign := ""
	if b < 0 {
		sign = "-"
		b = -b
	}
	for _, u := range []struct {
		name string
		size int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"kB", 1 << 10},
	} {
		if b >= u.size && b%u.size == 0 {
			return sign + strconv.FormatInt(b/u.size, 10) + u.name
		}
	}
	return sign + strconv.FormatInt(b, 10) + "B"
}

func trimFloatString(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
