package postgresconfig

import "testing"

func TestNormalizeGucValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "on uppercase", in: "ON", want: "on"},
		{name: "on mixed", in: " On ", want: "on"},
		{name: "true maps on", in: "true", want: "on"},
		{name: "yes maps on", in: "yes", want: "on"},
		{name: "off lowercase", in: "off", want: "off"},
		{name: "false maps off", in: "false", want: "off"},
		{name: "size lowercased", in: "128MB", want: "128mb"},
		{name: "empty", in: "  ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeGucValue(tt.in); got != tt.want {
				t.Fatalf("NormalizeGucValue(%q)=%q want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGucValuesEqual_MemoryAndTimeUnits(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "8MB equals 8192kB", a: "8MB", b: "8192kB", want: true},
		{name: "8MB equals bare bytes", a: "8MB", b: "8388608", want: true},
		{name: "128MB equals 128mb case", a: "128MB", b: "128mb", want: true},
		{name: "different memory sizes", a: "8MB", b: "16MB", want: false},
		{name: "5min equals 300s", a: "5min", b: "300s", want: true},
		{name: "1s equals 1000ms", a: "1s", b: "1000ms", want: true},
		{name: "bool still works", a: "ON", b: "true", want: true},
		{name: "plain strings unequal", a: "md5", b: "scram-sha-256", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gucValuesEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("gucValuesEqual(%q,%q)=%v want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareAgainstBaseline_PgSettingsUnits(t *testing.T) {
	// pg_settings-style: setting is unitless number, unit is separate (packed into map).
	baseline := PackGucSnapshotBundle(GucSnapshotBundle{
		Settings: map[string]string{"shared_buffers": "1024", "work_mem": "4096"},
		Units:    map[string]string{"shared_buffers": "8kB", "work_mem": "kB"},
		Vartypes: map[string]string{"shared_buffers": "integer", "work_mem": "integer"},
	})
	// Equivalent memory expressed with different unit metadata.
	live := PackGucSnapshotBundle(GucSnapshotBundle{
		Settings: map[string]string{"shared_buffers": "8", "work_mem": "4"},
		Units:    map[string]string{"shared_buffers": "MB", "work_mem": "MB"},
		Vartypes: map[string]string{"shared_buffers": "integer", "work_mem": "integer"},
	})
	rows := CompareAgainstBaseline(baseline, live)
	for _, row := range rows {
		if row.Status != DriftMatch {
			t.Fatalf("%s status=%q want match (baseline=%q live=%q)", row.GUC, row.Status, row.Baseline, row.Live)
		}
	}
}

func TestGucValuesEqualWithUnits_MixedHuman(t *testing.T) {
	tests := []struct {
		name               string
		a, unitA, b, unitB string
		want               bool
	}{
		{name: "pg 8kB blocks vs human 8MB", a: "1024", unitA: "8kB", b: "8MB", unitB: "", want: true},
		{name: "pg kB vs bare bytes", a: "8192", unitA: "kB", b: "8388608", unitB: "", want: true},
		{name: "different sizes", a: "1024", unitA: "8kB", b: "16MB", unitB: "", want: false},
		{name: "time ms vs s", a: "5000", unitA: "ms", b: "5", unitB: "s", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gucValuesEqualWithUnits(tt.a, tt.unitA, tt.b, tt.unitB); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestCompareAgainstBaseline(t *testing.T) {
	baseline := map[string]string{
		"ssl":             "on",
		"shared_buffers":  "128MB",
		"max_connections": "200",
	}

	tests := []struct {
		name       string
		live       map[string]string
		wantStatus map[string]DriftStatus
	}{
		{
			name: "all match case insensitive",
			live: map[string]string{
				"ssl":             "ON",
				"shared_buffers":  "128mb",
				"max_connections": "200",
			},
			wantStatus: map[string]DriftStatus{
				"ssl": DriftMatch, "shared_buffers": DriftMatch, "max_connections": DriftMatch,
			},
		},
		{
			name: "one drift",
			live: map[string]string{
				"ssl":             "off",
				"shared_buffers":  "128MB",
				"max_connections": "200",
			},
			wantStatus: map[string]DriftStatus{
				"ssl": DriftDiff, "shared_buffers": DriftMatch, "max_connections": DriftMatch,
			},
		},
		{
			name: "missing key",
			live: map[string]string{
				"shared_buffers":  "128MB",
				"max_connections": "200",
			},
			wantStatus: map[string]DriftStatus{
				"ssl": DriftMissing, "shared_buffers": DriftMatch, "max_connections": DriftMatch,
			},
		},
		{
			name:       "empty live map",
			live:       map[string]string{},
			wantStatus: map[string]DriftStatus{"ssl": DriftMissing, "shared_buffers": DriftMissing, "max_connections": DriftMissing},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := CompareAgainstBaseline(baseline, tt.live)
			if len(rows) != len(tt.wantStatus) {
				t.Fatalf("len(rows)=%d want %d", len(rows), len(tt.wantStatus))
			}
			for _, row := range rows {
				want, ok := tt.wantStatus[row.GUC]
				if !ok {
					t.Fatalf("unexpected guc %q", row.GUC)
				}
				if row.Status != want {
					t.Fatalf("%s: status=%q want %q (baseline=%q live=%q)", row.GUC, row.Status, want, row.Baseline, row.Live)
				}
			}
		})
	}
}

func TestCompareAgainstBaseline_EmptyValues(t *testing.T) {
	tests := []struct {
		name         string
		baseline     map[string]string
		live         map[string]string
		wantStatus   DriftStatus
		wantLive     string
		wantBaseline string
	}{
		{
			name:         "empty on both sides matches",
			baseline:     map[string]string{"application_name": ""},
			live:         map[string]string{"application_name": ""},
			wantStatus:   DriftMatch,
			wantLive:     "",
			wantBaseline: "",
		},
		{
			name:         "whitespace values normalize and match",
			baseline:     map[string]string{"cluster_name": " "},
			live:         map[string]string{"cluster_name": "\t"},
			wantStatus:   DriftMatch,
			wantLive:     "", // FormatGucDisplay trims whitespace-only values
			wantBaseline: "",
		},
		{
			name:         "empty baseline and non-empty live drift",
			baseline:     map[string]string{"default_tablespace": ""},
			live:         map[string]string{"default_tablespace": "fastspace"},
			wantStatus:   DriftDiff,
			wantLive:     "fastspace",
			wantBaseline: "",
		},
		{
			name:         "non-empty baseline and empty live drift",
			baseline:     map[string]string{"application_name": "kshield"},
			live:         map[string]string{"application_name": ""},
			wantStatus:   DriftDiff,
			wantLive:     "",
			wantBaseline: "kshield",
		},
		{
			name:         "absent live key is missing",
			baseline:     map[string]string{"bonjour_name": ""},
			live:         map[string]string{},
			wantStatus:   DriftMissing,
			wantLive:     "-",
			wantBaseline: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := CompareAgainstBaseline(tt.baseline, tt.live)
			if len(rows) != 1 {
				t.Fatalf("len(rows)=%d want 1", len(rows))
			}
			row := rows[0]
			if row.Status != tt.wantStatus {
				t.Fatalf("status=%q want %q", row.Status, tt.wantStatus)
			}
			if row.Live != tt.wantLive {
				t.Fatalf("live=%q want %q", row.Live, tt.wantLive)
			}
			if row.Baseline != tt.wantBaseline {
				t.Fatalf("baseline=%q want %q", row.Baseline, tt.wantBaseline)
			}
		})
	}
}

func TestCompareAgainstBaseline_KeyCaseAndConfOnly(t *testing.T) {
	baseline := map[string]string{
		"datestyle":   "iso, mdy",
		"timezone":    "Etc/UTC",
		"include_dir": "conf.d",
		"ssl":         "on",
	}
	live := map[string]string{
		"DateStyle": "ISO, MDY",
		"TimeZone":  "Etc/UTC",
		"ssl":       "on",
	}

	rows := CompareAgainstBaseline(baseline, live)
	statusBy := map[string]DriftStatus{}
	for _, row := range rows {
		statusBy[row.GUC] = row.Status
	}
	if _, ok := statusBy["include_dir"]; ok {
		t.Fatal("include_dir is conf-only and must be skipped")
	}
	if statusBy["datestyle"] != DriftMatch {
		t.Fatalf("datestyle=%q want match", statusBy["datestyle"])
	}
	if statusBy["timezone"] != DriftMatch {
		t.Fatalf("timezone=%q want match", statusBy["timezone"])
	}
	if statusBy["ssl"] != DriftMatch {
		t.Fatalf("ssl=%q want match", statusBy["ssl"])
	}
	if len(rows) != 3 {
		t.Fatalf("len(rows)=%d want 3", len(rows))
	}
}

func TestNormalizeGucSettings(t *testing.T) {
	got := NormalizeGucSettings(map[string]string{
		"DateStyle":   "ISO, MDY",
		"include_dir": "conf.d",
		" SSL ":       "on",
	})
	if len(got) != 2 {
		t.Fatalf("len=%d want 2: %+v", len(got), got)
	}
	if got["datestyle"] != "ISO, MDY" {
		t.Fatalf("datestyle=%q", got["datestyle"])
	}
	if got["ssl"] != "on" {
		t.Fatalf("ssl=%q", got["ssl"])
	}
	if _, ok := got["include_dir"]; ok {
		t.Fatal("include_dir should be dropped")
	}
}
