package config

import (
	"fmt"
	"slices"
	"strings"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	shieldcron "github.com/klouddb/klouddbshield/pkg/cron"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

var logParserScanTokens = []string{
	"inactive_users",
	"unique_ip",
	"unused_lines",
	"password_leak_scanner",
}

// CommandsFromPostgres expands collector scan_commands into cron Command entries.
func CommandsFromPostgres(pg *postgresdb.Postgres, scanCommandsRaw string, lp *LogParserCronInput) ([]Command, error) {
	targets := pg.ExpandTargets()
	if len(targets) == 0 {
		return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}
	commands := parseScanCommands(scanCommandsRaw)
	if len(commands) == 0 {
		commands = []string{"postgres_cis", "hba_scanner"}
	}
	if slices.Contains(commands, "all") {
		resolved, err := resolveLogParserInput(lp, true)
		if err != nil {
			return nil, err
		}
		return []Command{{
			Name:      cons.RootCMD_All,
			Postgres:  targets,
			LogParser: resolved,
		}}, nil
	}

	out := make([]Command, 0, len(commands))
	for _, cmd := range commands {
		switch cmd {
		case "postgres_cis":
			out = append(out, Command{Name: cons.RootCMD_PostgresCIS, Postgres: targets})
		case "hba_scanner":
			out = append(out, Command{Name: cons.RootCMD_HBAScanner, Postgres: targets})
		case "guc_drift":
			out = append(out, Command{Name: cons.RootCMD_GucDrift, Postgres: targets})
		case "ssl_check", "ssl_audit":
			out = append(out, Command{Name: cons.RootCMD_SSLCheck, Postgres: targets})
		case "pii_scanner":
			out = append(out, Command{Name: cons.RootCMD_PiiScanner, Postgres: targets})
		case "backup_compliance":
			out = append(out, Command{Name: cons.RootCMD_BackupCompliance, Postgres: targets})
		case "inactive_users":
			c, err := logParserCommand(targets, lp, cons.LogParserCMD_InactiveUser, false)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		case "unique_ip":
			c, err := logParserCommand(targets, lp, cons.LogParserCMD_UniqueIPs, false)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		case "unused_lines":
			c, err := logParserCommand(targets, lp, cons.LogParserCMD_HBAUnusedLines, true)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		case "password_leak_scanner":
			c, err := logParserCommand(targets, lp, cons.LogParserCMD_PasswordLeakScanner, false)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		default:
			return nil, fmt.Errorf("unsupported scan command %q for %s:%s/%s", cmd, targets[0].Host, targets[0].Port, targets[0].DBName)
		}
	}
	return out, nil
}

func logParserCommand(targets []*postgresdb.Postgres, lp *LogParserCronInput, name string, requireHBA bool) (Command, error) {
	resolved, err := resolveLogParserInput(lp, requireHBA)
	if err != nil {
		return Command{}, fmt.Errorf("%s: %w", name, err)
	}
	return Command{
		Name:      name,
		Postgres:  targets,
		LogParser: resolved,
	}, nil
}

func resolveLogParserInput(lp *LogParserCronInput, requireHBA bool) (*LogParserCronInput, error) {
	if lp == nil {
		lp = &LogParserCronInput{}
	}
	cp := *lp
	if strings.TrimSpace(cp.Prefix) == "" {
		cp.Prefix = DefaultLogPrefix()
	}
	if strings.TrimSpace(cp.LogFile) == "" {
		return nil, fmt.Errorf("logparser logfile required in [collector.logparser]")
	}
	if requireHBA && strings.TrimSpace(cp.HbaConfFile) == "" {
		return nil, fmt.Errorf("logparser hbaconffile required for unused_lines")
	}
	return &cp, nil
}

// BuildCollectorScheduleMap returns cron schedule -> commands for ciscollector --setup-cron.
// Sources (merged):
//   - [collector] schedule + scan_commands (optional [piiscanner].schedule, [collector.logparser].schedule)
//   - legacy [[crons]] blocks (same format as upstream klouddbshield)
func (c *Config) BuildCollectorScheduleMap() (map[string][]Command, error) {
	out := map[string][]Command{}
	if c == nil {
		return out, nil
	}

	if c.CollectorScheduleReady() {
		allCmds, err := CommandsFromPostgres(c.Postgres, c.Collector.ScanCommands, c.Collector.LogParser)
		if err != nil {
			return nil, err
		}

		collectorSched := strings.TrimSpace(c.Collector.Schedule)
		piiSched := strings.TrimSpace(c.PiiScanner.Schedule)
		logSched := logParserSchedule(c)
		scanRaw := c.Collector.ScanCommands

		useSeparatePii := piiSched != "" && scanCommandsIncludePii(scanRaw)
		useSeparateLog := logSched != "" && scanCommandsIncludeLogParser(scanRaw)

		var mainCmds, piiCmds, logCmds []Command
		if slices.Contains(parseScanCommands(scanRaw), "all") && (useSeparatePii || useSeparateLog) {
			var err error
			mainCmds, piiCmds, logCmds, err = c.expandAllScheduleCommands()
			if err != nil {
				return nil, err
			}
		} else if !useSeparatePii && !useSeparateLog {
			assignScheduleCommands(out, collectorSched, allCmds)
			mainCmds = nil
		} else {
			mainCmds, piiCmds, logCmds = partitionScheduledCommands(allCmds)
		}

		if mainCmds != nil || piiCmds != nil || logCmds != nil {
			if !useSeparatePii {
				mainCmds = append(mainCmds, piiCmds...)
				piiCmds = nil
			}
			if !useSeparateLog {
				mainCmds = append(mainCmds, logCmds...)
				logCmds = nil
			}
			assignScheduleCommands(out, collectorSched, mainCmds)
			assignScheduleCommands(out, piiSched, piiCmds)
			assignScheduleCommands(out, logSched, logCmds)
		}
	}

	if err := c.mergeLegacyCrons(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Config) mergeLegacyCrons(out map[string][]Command) error {
	for i, cr := range c.Crons {
		sched := strings.TrimSpace(cr.Schedule)
		if sched == "" {
			return fmt.Errorf("[[crons]] entry %d: schedule is required", i+1)
		}
		ok, err := shieldcron.IsLessThan24Hours(sched)
		if err != nil {
			return fmt.Errorf("[[crons]] entry %d schedule %q: %w", i+1, sched, err)
		}
		if !ok {
			return fmt.Errorf("[[crons]] entry %d schedule %q: frequency must be at least 24 hours between runs", i+1, sched)
		}
		if len(cr.Commands) == 0 {
			continue
		}
		out[sched] = append(out[sched], cr.Commands...)
	}
	return nil
}

func logParserSchedule(c *Config) string {
	if c == nil || c.Collector.LogParser == nil {
		return ""
	}
	return strings.TrimSpace(c.Collector.LogParser.Schedule)
}

func assignScheduleCommands(out map[string][]Command, sched string, cmds []Command) {
	if strings.TrimSpace(sched) == "" || len(cmds) == 0 {
		return
	}
	out[sched] = append(out[sched], cmds...)
}

func parseScanCommands(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func scanCommandsIncludePii(raw string) bool {
	cmds := parseScanCommands(raw)
	return slices.Contains(cmds, "pii_scanner") || slices.Contains(cmds, "all")
}

func scanCommandsIncludeLogParser(raw string) bool {
	cmds := parseScanCommands(raw)
	if slices.Contains(cmds, "all") {
		return true
	}
	for _, token := range cmds {
		if slices.Contains(logParserScanTokens, token) {
			return true
		}
	}
	return false
}

// expandAllScheduleCommands splits scan_commands=all into core, PII, and log-parser buckets for separate crons.
func (c *Config) expandAllScheduleCommands() (main, pii, log []Command, err error) {
	if c == nil || c.Postgres == nil {
		return nil, nil, nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}
	targets := c.Postgres.ExpandTargets()
	if len(targets) == 0 {
		return nil, nil, nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}
	main = []Command{{Name: cons.RootCMD_AllCore, Postgres: targets}}
	pii = []Command{{Name: cons.RootCMD_PiiScanner, Postgres: targets}}
	for _, name := range logParserScanTokens {
		cmd, err := logParserCommand(targets, c.Collector.LogParser, name, name == "unused_lines")
		if err != nil {
			return nil, nil, nil, err
		}
		log = append(log, cmd)
	}
	return main, pii, log, nil
}

func isLogParserRootCommand(name string) bool {
	switch name {
	case cons.LogParserCMD_InactiveUser,
		cons.LogParserCMD_UniqueIPs,
		cons.LogParserCMD_HBAUnusedLines,
		cons.LogParserCMD_PasswordLeakScanner:
		return true
	default:
		return false
	}
}

func partitionScheduledCommands(cmds []Command) (main, pii, log []Command) {
	for _, cmd := range cmds {
		switch {
		case cmd.Name == cons.RootCMD_PiiScanner:
			pii = append(pii, cmd)
		case isLogParserRootCommand(cmd.Name):
			log = append(log, cmd)
		default:
			main = append(main, cmd)
		}
	}
	return main, pii, log
}
