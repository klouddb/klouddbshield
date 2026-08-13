package config

import (
	"testing"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

func TestBackupComplianceTargetsFromCrons(t *testing.T) {
	cfg := &Config{
		BackupCompliance: BackupComplianceInput{Enabled: true},
		Crons: []Cron{{
			Schedule: "*/2 * * * *",
			Commands: []Command{{
				Name: "backup_compliance",
				Postgres: []*postgresdb.Postgres{
					{Host: "172.27.105.18", Port: "5432", User: "postgres", Password: "p", DBName: "postgres"},
					{Host: "localhost", Port: "5434", User: "postgres", Password: "p", DBName: "postgres"},
				},
			}},
		}},
	}

	targets := cfg.BackupComplianceTargets()
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Host != "172.27.105.18" || targets[1].Host != "localhost" {
		t.Fatalf("unexpected targets: %+v %+v", targets[0], targets[1])
	}
	if cfg.HasCronPostgres() != true {
		t.Fatal("HasCronPostgres should be true")
	}
}

func TestBackupComplianceTargetsFallsBackToPostgres(t *testing.T) {
	cfg := &Config{
		Postgres: &postgresdb.Postgres{Host: "localhost", Port: "5432", User: "u", Password: "p", DBName: "db"},
	}
	targets := cfg.BackupComplianceTargets()
	if len(targets) != 1 || targets[0].Host != "localhost" {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}
