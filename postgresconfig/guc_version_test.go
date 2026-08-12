package postgresconfig

import (
	"sort"
	"testing"
)

func TestParsePostgresMajor(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "plain major.minor", in: "16.4", want: 16},
		{name: "postgresql prefix", in: "PostgreSQL 18.1", want: 18},
		{name: "major only", in: "15", want: 15},
		{name: "empty", in: "", want: 0},
		{name: "garbage", in: "not-a-version", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePostgresMajor(tt.in); got != tt.want {
				t.Fatalf("ParsePostgresMajor(%q)=%d want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestComposeGucVersionDiff_Pairs(t *testing.T) {
	tests := []struct {
		name        string
		from, to    int
		wantNew     int
		wantRemoved int
		wantUpdated int
		mustNew     []string
		mustRemoved []string
		mustUpdated []string
	}{
		{
			name: "15 to 16", from: 15, to: 16,
			wantNew: 13, wantRemoved: 3, wantUpdated: 0,
			mustNew:     []string{"vacuum_buffer_usage_limit", "scram_iterations"},
			mustRemoved: []string{"force_parallel_mode", "promote_trigger_file"},
		},
		{
			name: "16 to 17", from: 16, to: 17,
			wantNew: 19, wantRemoved: 3, wantUpdated: 1,
			mustNew:     []string{"allow_alter_system", "io_combine_limit"},
			mustRemoved: []string{"db_user_namespace", "old_snapshot_threshold"},
			mustUpdated: []string{"vacuum_buffer_usage_limit"},
		},
		{
			name: "17 to 18", from: 17, to: 18,
			wantNew: 20, wantRemoved: 1, wantUpdated: 3,
			mustNew:     []string{"io_method", "ssl_groups"},
			mustRemoved: []string{"ssl_ecdh_curve"},
			mustUpdated: []string{"effective_io_concurrency", "log_connections", "maintenance_io_concurrency"},
		},
		{
			name: "15 to 18 composed", from: 15, to: 18,
			wantNew: 52, wantRemoved: 7, wantUpdated: 4,
			mustNew:     []string{"io_method", "allow_alter_system", "vacuum_buffer_usage_limit"},
			mustRemoved: []string{"force_parallel_mode", "ssl_ecdh_curve", "db_user_namespace"},
			mustUpdated: []string{"effective_io_concurrency", "vacuum_buffer_usage_limit"},
		},
		{
			name: "16 to 18", from: 16, to: 18,
			wantNew: 39, wantRemoved: 4, wantUpdated: 4,
			mustNew:     []string{"io_method", "allow_alter_system"},
			mustRemoved: []string{"ssl_ecdh_curve", "db_user_namespace"},
			mustUpdated: []string{"effective_io_concurrency", "vacuum_buffer_usage_limit"},
		},
		{
			name: "18 to 16 downgrade swaps", from: 18, to: 16,
			wantNew: 4, wantRemoved: 39, wantUpdated: 4,
			mustNew:     []string{"ssl_ecdh_curve", "db_user_namespace"},
			mustRemoved: []string{"io_method", "allow_alter_system"},
			mustUpdated: []string{"effective_io_concurrency"},
		},
		{
			name: "same major empty", from: 16, to: 16,
			wantNew: 0, wantRemoved: 0, wantUpdated: 0,
		},
		{
			name: "unsupported major empty", from: 14, to: 18,
			wantNew: 0, wantRemoved: 0, wantUpdated: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ComposeGucVersionDiff(tt.from, tt.to)
			if len(d.New) != tt.wantNew {
				t.Fatalf("new=%d want %d", len(d.New), tt.wantNew)
			}
			if len(d.Removed) != tt.wantRemoved {
				t.Fatalf("removed=%d want %d", len(d.Removed), tt.wantRemoved)
			}
			if len(d.Updated) != tt.wantUpdated {
				t.Fatalf("updated=%d want %d", len(d.Updated), tt.wantUpdated)
			}
			for _, n := range tt.mustNew {
				if _, ok := d.New[n]; !ok {
					t.Fatalf("missing new %q", n)
				}
			}
			for _, n := range tt.mustRemoved {
				if _, ok := d.Removed[n]; !ok {
					t.Fatalf("missing removed %q", n)
				}
			}
			for _, n := range tt.mustUpdated {
				if _, ok := d.Updated[n]; !ok {
					t.Fatalf("missing updated %q", n)
				}
			}
		})
	}
}

func TestInferGucMajorFromSettings(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		want int
	}{
		{
			name: "pg18 markers",
			keys: []string{"shared_buffers", "io_method", "ssl_groups"},
			want: 18,
		},
		{
			name: "pg17 markers",
			keys: []string{"shared_buffers", "allow_alter_system", "ssl_ecdh_curve"},
			want: 17,
		},
		{
			name: "pg16 markers",
			keys: []string{"shared_buffers", "vacuum_buffer_usage_limit", "db_user_namespace"},
			want: 16,
		},
		{
			name: "pg15 markers",
			keys: []string{"shared_buffers", "force_parallel_mode", "promote_trigger_file"},
			want: 15,
		},
		{
			name: "ambiguous plain settings",
			keys: []string{"shared_buffers", "max_connections"},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := map[string]string{}
			for _, k := range tt.keys {
				settings[k] = "1"
			}
			if got := InferGucMajorFromSettings(settings); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
		})
	}
}

func TestCompareAgainstBaseline_VersionAware(t *testing.T) {
	tests := []struct {
		name       string
		baseline   map[string]string
		live       map[string]string
		wantStatus map[string]DriftStatus
	}{
		{
			name: "same major unchanged drift",
			baseline: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings:  map[string]string{"shared_buffers": "128MB", "max_connections": "100"},
				PgMajor:   16,
				PgVersion: "16.4",
			}),
			live: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings:  map[string]string{"shared_buffers": "256MB", "max_connections": "100"},
				PgMajor:   16,
				PgVersion: "16.4",
			}),
			wantStatus: map[string]DriftStatus{
				"shared_buffers":  DriftDiff,
				"max_connections": DriftMatch,
			},
		},
		{
			name: "16 to 18 classifies updated removed and new",
			baseline: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings: map[string]string{
					"shared_buffers":           "128MB",
					"effective_io_concurrency": "1",
					"ssl_ecdh_curve":           "prime256v1",
					"db_user_namespace":        "off",
				},
				PgMajor:   16,
				PgVersion: "16.4",
			}),
			live: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings: map[string]string{
					"shared_buffers":           "128MB",
					"effective_io_concurrency": "16",
					"io_method":                "worker",
					"allow_alter_system":       "on",
				},
				PgMajor:   18,
				PgVersion: "18.0",
			}),
			wantStatus: map[string]DriftStatus{
				"shared_buffers":           DriftMatch,
				"effective_io_concurrency": DriftVersionUpdated,
				"ssl_ecdh_curve":           DriftVersionRemoved,
				"db_user_namespace":        DriftVersionRemoved,
				"io_method":                DriftVersionNew,
				"allow_alter_system":       DriftVersionNew,
			},
		},
		{
			name: "15 to 18 force_parallel removed",
			baseline: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings: map[string]string{
					"force_parallel_mode": "off",
					"work_mem":            "4MB",
				},
				PgMajor: 15,
			}),
			live: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings: map[string]string{
					"work_mem":  "4MB",
					"io_method": "worker",
				},
				PgMajor: 18,
			}),
			wantStatus: map[string]DriftStatus{
				"force_parallel_mode": DriftVersionRemoved,
				"work_mem":            DriftMatch,
				"io_method":           DriftVersionNew,
			},
		},
		{
			name: "real drift still reported across majors",
			baseline: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings: map[string]string{"max_connections": "200"},
				PgMajor:  16,
			}),
			live: PackGucSnapshotBundle(GucSnapshotBundle{
				Settings: map[string]string{"max_connections": "500", "io_method": "worker"},
				PgMajor:  18,
			}),
			wantStatus: map[string]DriftStatus{
				"max_connections": DriftDiff,
				"io_method":       DriftVersionNew,
			},
		},
		{
			name: "infer majors from markers when meta missing",
			baseline: map[string]string{
				"shared_buffers":     "128MB",
				"ssl_ecdh_curve":     "prime256v1",
				"allow_alter_system": "on",
			},
			live: map[string]string{
				"shared_buffers": "128MB",
				"io_method":      "worker",
				"ssl_groups":     "X25519:prime256v1",
			},
			wantStatus: map[string]DriftStatus{
				"shared_buffers": DriftMatch,
				"ssl_ecdh_curve": DriftVersionRemoved,
				"io_method":      DriftVersionNew,
				"ssl_groups":     DriftVersionNew,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := CompareAgainstBaseline(tt.baseline, tt.live)
			got := map[string]DriftStatus{}
			for _, r := range rows {
				got[r.GUC] = r.Status
			}
			for guc, want := range tt.wantStatus {
				if got[guc] != want {
					keys := make([]string, 0, len(got))
					for k := range got {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					t.Fatalf("%s status=%q want %q (all=%v)", guc, got[guc], want, got)
				}
			}
		})
	}
}

func TestIsVersionExpectedStatus(t *testing.T) {
	tests := []struct {
		status DriftStatus
		want   bool
	}{
		{DriftMatch, false},
		{DriftDiff, false},
		{DriftMissing, false},
		{DriftVersionUpdated, true},
		{DriftVersionNew, true},
		{DriftVersionRemoved, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := IsVersionExpectedStatus(tt.status); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
