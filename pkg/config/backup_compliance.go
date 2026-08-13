package config

import (
	"strings"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

// BackupComplianceInput holds [backup_compliance] settings from kshieldconfig.toml.
type BackupComplianceInput struct {
	Enabled      bool     `toml:"enabled"`
	ServerName   string   `toml:"server_name"`
	AllowedStart string   `toml:"allowed_start"`
	AllowedEnd   string   `toml:"allowed_end"`
	AllowedDays  []string `toml:"allowed_days"` // e.g. ["saturday","sunday"]; empty = every day
	Timezone     string   `toml:"timezone"`     // IANA e.g. Asia/Kolkata; empty = machine local
}

// HasCronPostgres is true when any [[crons.commands.postgres]] block is present.
func (c *Config) HasCronPostgres() bool {
	if c == nil {
		return false
	}
	for _, cron := range c.Crons {
		for _, cmd := range cron.Commands {
			if len(cmd.Postgres) > 0 {
				return true
			}
		}
	}
	return false
}

// BackupComplianceTargets returns postgres targets for backup compliance scans.
// Prefers [[crons]] entries named backup_compliance (or all when enabled);
// falls back to top-level [postgres].
func (c *Config) BackupComplianceTargets() []*postgresdb.Postgres {
	if c == nil {
		return nil
	}
	var out []*postgresdb.Postgres
	seen := map[string]bool{}
	add := func(p *postgresdb.Postgres) {
		if p == nil {
			return
		}
		for _, t := range p.ExpandTargets() {
			if t == nil {
				continue
			}
			key := t.Host + ":" + t.Port + "/" + t.DBName
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, t)
		}
	}

	for _, cron := range c.Crons {
		for _, cmd := range cron.Commands {
			name := strings.TrimSpace(cmd.Name)
			include := name == cons.RootCMD_BackupCompliance ||
				(name == cons.RootCMD_All && c.BackupCompliance.Enabled)
			if !include {
				continue
			}
			for _, p := range cmd.Postgres {
				add(p)
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	return c.PostgresTargets()
}
