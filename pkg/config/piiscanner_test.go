package config

import (
	"strings"
	"testing"

	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

func TestBuildPiiScannerConfig(t *testing.T) {
	pg := &postgresdb.Postgres{
		Host:   "localhost",
		Port:   "5432",
		DBName: "defaultdb",
	}

	tests := []struct {
		name    string
		cfg     *Config
		pg      *postgresdb.Postgres
		over    PiiScannerOverrides
		wantErr string
		check   func(t *testing.T, got *piiscanner.Config)
	}{
		{
			name: "defaults from empty TOML section",
			cfg:  &Config{},
			pg:   pg,
			check: func(t *testing.T, got *piiscanner.Config) {
				t.Helper()
				if got == nil {
					t.Fatal("expected config")
				}
			},
		},
		{
			name: "TOML values applied",
			cfg: &Config{
				PiiScanner: PiiScannerInput{
					RunOption:     "metascan",
					Database:      "appdb",
					Schema:        "custom",
					ExcludeTables: "audit_log",
					IncludeTables: "users",
				},
			},
			pg: pg,
			check: func(t *testing.T, got *piiscanner.Config) {
				t.Helper()
				if got == nil {
					t.Fatal("expected config")
				}
			},
		},
		{
			name: "CLI overrides TOML",
			cfg: &Config{
				PiiScanner: PiiScannerInput{
					RunOption: "datascan",
					Schema:    "public",
				},
			},
			pg: pg,
			over: PiiScannerOverrides{
				RunOption: "deepscan",
				Schema:    "other",
				Database:  "cli_db",
			},
			check: func(t *testing.T, got *piiscanner.Config) {
				t.Helper()
				if got == nil {
					t.Fatal("expected config")
				}
			},
		},
		{
			name: "region india from TOML",
			cfg: &Config{
				PiiScanner: PiiScannerInput{
					RunOption: "datascan",
					Region:    "india",
				},
			},
			pg: pg,
			check: func(t *testing.T, got *piiscanner.Config) {
				t.Helper()
				if got.Region != piiscanner.RegionIndia {
					t.Fatalf("region: got %q want %q", got.Region, piiscanner.RegionIndia)
				}
			},
		},
		{
			name: "invalid region",
			cfg: &Config{
				PiiScanner: PiiScannerInput{Region: "us"},
			},
			pg:      pg,
			wantErr: "invalid pii region",
		},
		{
			name:    "invalid run option",
			cfg:     &Config{PiiScanner: PiiScannerInput{RunOption: "not_a_mode"}},
			pg:      pg,
			wantErr: "invalid run option",
		},
		{
			name:    "missing postgres",
			cfg:     &Config{},
			pg:      nil,
			wantErr: "kshieldconfig",
		},
		{
			name:    "nil config",
			cfg:     nil,
			pg:      pg,
			wantErr: "config is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.BuildPiiScannerConfig(tt.pg, tt.over)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestPiiScannerInput_merged(t *testing.T) {
	tests := []struct {
		name       string
		in         PiiScannerInput
		over       PiiScannerOverrides
		wantRun    string
		wantDB     string
		wantSchema string
		wantExcl   string
		wantIncl   string
		wantRegion string
	}{
		{
			name:       "empty defaults to datascan and public",
			in:         PiiScannerInput{},
			wantRun:    piiscanner.RunOption_DataScan_String,
			wantSchema: "public",
		},
		{
			name: "TOML values preserved",
			in: PiiScannerInput{
				RunOption:     "metascan",
				Database:      "hej",
				Schema:        "app",
				ExcludeTables: "t1,t2",
				IncludeTables: "users",
				Region:        "india",
			},
			wantRun:    "metascan",
			wantDB:     "hej",
			wantSchema: "app",
			wantExcl:   "t1,t2",
			wantIncl:   "users",
			wantRegion: "india",
		},
		{
			name: "CLI overrides non-empty fields",
			in: PiiScannerInput{
				RunOption: "datascan",
				Schema:    "public",
				Region:    "",
			},
			over: PiiScannerOverrides{
				RunOption:     "deepscan",
				Database:      "other",
				ExcludeTables: "skip",
				Region:        "india",
			},
			wantRun:    "deepscan",
			wantDB:     "other",
			wantSchema: "public",
			wantExcl:   "skip",
			wantRegion: "india",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, db, schema, excl, incl, region := tt.in.merged(tt.over)
			if run != tt.wantRun {
				t.Errorf("run_option: got %q want %q", run, tt.wantRun)
			}
			if db != tt.wantDB {
				t.Errorf("database: got %q want %q", db, tt.wantDB)
			}
			if schema != tt.wantSchema {
				t.Errorf("schema: got %q want %q", schema, tt.wantSchema)
			}
			if excl != tt.wantExcl {
				t.Errorf("exclude: got %q want %q", excl, tt.wantExcl)
			}
			if incl != tt.wantIncl {
				t.Errorf("include: got %q want %q", incl, tt.wantIncl)
			}
			if region != tt.wantRegion {
				t.Errorf("region: got %q want %q", region, tt.wantRegion)
			}
		})
	}
}
