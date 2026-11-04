package config

import (
	"fmt"
	"strings"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// PiiScannerInput holds [piiscanner] settings from kshieldconfig.toml.
type PiiScannerInput struct {
	Schedule      string `toml:"schedule"`
	RunOption     string `toml:"run_option"`
	Database      string `toml:"database"`
	Schema        string `toml:"schema"`
	ExcludeTables string `toml:"exclude_tables"`
	IncludeTables string `toml:"include_tables"`
	Region        string `toml:"region"`
}

// PiiScannerOverrides supplies CLI flag values that override TOML when non-empty.
type PiiScannerOverrides struct {
	RunOption     string
	Database      string
	Schema        string
	ExcludeTables string
	IncludeTables string
	Region        string
	PrintAll      bool
	SpacyOnly     bool
	PrintSummary  bool
}

func (in PiiScannerInput) merged(ov PiiScannerOverrides) (runOption, database, schema, exclude, include, region string) {
	runOption = strings.TrimSpace(in.RunOption)
	if s := strings.TrimSpace(ov.RunOption); s != "" {
		runOption = s
	}
	if runOption == "" {
		runOption = piiscanner.RunOption_DataScan_String
	}

	database = strings.TrimSpace(in.Database)
	if s := strings.TrimSpace(ov.Database); s != "" {
		database = s
	}

	schema = strings.TrimSpace(in.Schema)
	if schema == "" {
		schema = "public"
	}
	if s := strings.TrimSpace(ov.Schema); s != "" {
		schema = s
	}

	exclude = strings.TrimSpace(in.ExcludeTables)
	if s := strings.TrimSpace(ov.ExcludeTables); s != "" {
		exclude = s
	}

	include = strings.TrimSpace(in.IncludeTables)
	if s := strings.TrimSpace(ov.IncludeTables); s != "" {
		include = s
	}

	region = strings.TrimSpace(in.Region)
	if s := strings.TrimSpace(ov.Region); s != "" {
		region = s
	}
	return
}

// BuildPiiScannerConfig merges [piiscanner] TOML with optional CLI overrides.
func (c *Config) BuildPiiScannerConfig(pg *postgresdb.Postgres, ov PiiScannerOverrides) (*piiscanner.Config, error) {
	if pg == nil {
		return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}
	if c == nil {
		return nil, fmt.Errorf("config is nil")
	}
	runOption, database, schema, exclude, include, region := c.PiiScanner.merged(ov)
	return piiscanner.NewConfigWithRegion(pg, runOption, exclude, include, database, schema, region,
		ov.PrintAll, ov.SpacyOnly, ov.PrintSummary)
}
