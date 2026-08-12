package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/backupcompliance"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/mainserverclient"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

type backupComplianceRunner struct {
	postgresConfig *postgresdb.Postgres
	shieldConfig   *config.Config
}

func newBackupComplianceRunner(postgresConfig *postgresdb.Postgres, shieldConfig *config.Config) *backupComplianceRunner {
	return &backupComplianceRunner{
		postgresConfig: postgresConfig,
		shieldConfig:   shieldConfig,
	}
}

func (b *backupComplianceRunner) cronProcess(ctx context.Context) error {
	return b.run(ctx, "cron")
}

func (b *backupComplianceRunner) run(ctx context.Context, trigger string) error {
	if b.postgresConfig == nil {
		return fmt.Errorf("postgres config is required for backup compliance")
	}
	store, _, err := postgresdb.Open(*b.postgresConfig)
	if err != nil {
		return fmt.Errorf("error opening postgres connection: %v", err)
	}
	defer store.Close()

	rows, err := backupcompliance.QueryBackups(ctx, store)
	if err != nil {
		return err
	}

	policy, policySource := resolveBackupCompliancePolicy(ctx, b.shieldConfig)
	host := backupComplianceHost(b.postgresConfig, b.shieldConfig)

	report := backupcompliance.BuildReport(host, policy, rows, time.Now().UTC())
	printBackupComplianceSummary(report, policySource)

	payload := backupcompliance.ReportToMap(report)
	stampBackupPolicySource(payload, policySource)
	if err := pushBackupComplianceToMainServer(b.shieldConfig, b.postgresConfig, payload, trigger); err != nil {
		fmt.Printf("> Warning: backup compliance push to main-server failed: %v\n", err)
	}
	return nil
}

func stampBackupPolicySource(payload map[string]interface{}, policySource string) {
	if payload == nil {
		return
	}
	pol, _ := payload["policy"].(map[string]interface{})
	if pol == nil {
		pol = map[string]interface{}{}
		payload["policy"] = pol
	}
	switch policySource {
	case "dashboard":
		pol["policy_source"] = "dashboard"
	case "config":
		pol["policy_source"] = "collector_config"
	default:
		pol["policy_source"] = "none"
	}
}

func backupCompliancePolicy(cnf *config.Config) backupcompliance.Policy {
	policy := backupcompliance.Policy{}
	if cnf != nil {
		policy.AllowedStart = strings.TrimSpace(cnf.BackupCompliance.AllowedStart)
		policy.AllowedEnd = strings.TrimSpace(cnf.BackupCompliance.AllowedEnd)
		policy.Timezone = strings.TrimSpace(cnf.BackupCompliance.Timezone)
		for _, d := range cnf.BackupCompliance.AllowedDays {
			d = strings.TrimSpace(d)
			if d != "" {
				policy.AllowedDays = append(policy.AllowedDays, d)
			}
		}
	}
	return policy
}

// resolveBackupCompliancePolicy prefers local kshieldconfig.toml; if empty, uses dashboard DB via API.
func resolveBackupCompliancePolicy(ctx context.Context, cnf *config.Config) (backupcompliance.Policy, string) {
	local := backupCompliancePolicy(cnf)
	if backupcompliance.PolicyConfigured(local) {
		return local, "config"
	}
	if cnf == nil || !cnf.MainServer.Enabled {
		return local, "none"
	}
	client, err := mainserverclient.New(cnf)
	if err != nil {
		fmt.Printf("> Warning: cannot load dashboard backup window: %v\n", err)
		return local, "none"
	}
	dash, configured, err := client.GetBackupCompliancePolicy(ctx)
	if err != nil {
		fmt.Printf("> Warning: cannot load dashboard backup window: %v\n", err)
		return local, "none"
	}
	if !configured || !backupcompliance.PolicyConfigured(dash) {
		return local, "none"
	}
	// Keep local timezone if dashboard did not set one.
	if strings.TrimSpace(dash.Timezone) == "" && strings.TrimSpace(local.Timezone) != "" {
		dash.Timezone = local.Timezone
	}
	return dash, "dashboard"
}

func backupComplianceHost(pg *postgresdb.Postgres, cnf *config.Config) string {
	if cnf != nil {
		if name := strings.TrimSpace(cnf.BackupCompliance.ServerName); name != "" {
			return name
		}
	}
	if pg != nil && strings.TrimSpace(pg.Host) != "" {
		port := pg.Port
		if port == "" {
			port = "5432"
		}
		agent := ""
		if cnf != nil {
			agent = cnf.App.Hostname
		}
		host := reportstore.ResolveTargetHost(pg.Host, agent)
		return fmt.Sprintf("%s:%s", host, port)
	}
	return ""
}

func printBackupComplianceSummary(r backupcompliance.Report, policySource string) {
	fmt.Printf("\n> Backup Compliance for %s\n", r.Host)
	fmt.Printf("  Total: %d  Successful: %d  Failed: %d  Unauthorized: %d\n",
		r.Summary.TotalBackups, r.Summary.Successful, r.Summary.Failed, r.Summary.Unauthorized)
	if r.Policy.AllowedStart != "" || r.Policy.AllowedEnd != "" || len(r.Policy.AllowedDays) > 0 {
		window := fmt.Sprintf("%s – %s", r.Policy.AllowedStart, r.Policy.AllowedEnd)
		if len(r.Policy.AllowedDays) > 0 {
			window = strings.Join(r.Policy.AllowedDays, ", ") + " " + window
		}
		src := policySource
		if src == "" {
			src = "config"
		}
		fmt.Printf("  Window: %s (%s)\n", window, src)
	} else {
		fmt.Printf("  Window: not configured\n")
	}
	for i, b := range r.Backups {
		if i >= 10 {
			fmt.Printf("  … and %d more\n", len(r.Backups)-10)
			break
		}
		fmt.Printf("  - %s %s %s %s [%s]\n", b.StartTime, b.BackupType, b.Database, b.Status, b.ComplianceStatus)
	}
	fmt.Println()
}

func pushBackupComplianceToMainServer(cnf *config.Config, pg *postgresdb.Postgres, reportJSON map[string]interface{}, trigger string) error {
	if cnf == nil || !cnf.MainServer.Enabled || pg == nil || len(reportJSON) == 0 {
		return nil
	}
	client, err := mainserverclient.New(cnf)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mainserverclient.PushBackupComplianceReport(ctx, cnf, client, pg, reportJSON, trigger); err != nil {
		return err
	}
	_ = client.FlushRetries(ctx)
	return nil
}
