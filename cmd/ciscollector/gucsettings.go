package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/postgresconfig"
)

const gucSettingsReportKey = "GUC Settings"

type gucSettingsRunner struct {
	pg *postgresdb.Postgres
}

func newGucSettingsRunner(pg *postgresdb.Postgres) *gucSettingsRunner {
	return &gucSettingsRunner{pg: pg}
}

func (g *gucSettingsRunner) cronProcess(ctx context.Context) error {
	return g.run(ctx)
}

func (g *gucSettingsRunner) run(_ context.Context) error {
	if g.pg == nil {
		return fmt.Errorf("postgres config missing for guc settings")
	}
	_, err := fetchGucSettingsMap(g.pg)
	return err
}

func fetchGucSettingsMap(pg *postgresdb.Postgres) (map[string]string, error) {
	if pg == nil {
		return nil, fmt.Errorf("postgres config missing for guc settings")
	}
	cp := *pg
	cp.DBName = cp.PrimaryDBName()
	connStr := postgresdb.BuildConnectionString(cp)
	bundle, err := postgresconfig.GetPgSettingsBundleFromConnectionString(connStr)
	if err != nil {
		return nil, err
	}
	return postgresconfig.PackGucSnapshotBundle(bundle), nil
}

func embedGucSettingsInFileData(fileData map[string]interface{}, settings map[string]string, startedAt, finishedAt time.Time) {
	if fileData == nil || len(settings) == 0 {
		return
	}
	fileData[gucSettingsReportKey] = map[string]interface{}{
		"settings":    settings,
		"source":      "pg_settings",
		"started_at":  startedAt.UTC(),
		"finished_at": finishedAt.UTC(),
	}
}

// collectGucIntoScanPayload runs pg_settings and embeds settings into the scan payload.
func collectGucIntoScanPayload(
	cnf *config.Config,
	pg *postgresdb.Postgres,
	fileData map[string]interface{},
	startedAt, finishedAt time.Time,
	features []string,
	runErr string,
) ([]string, string) {
	if cnf == nil || !cnf.MainServer.Enabled || pg == nil {
		return features, runErr
	}
	settings, err := fetchGucSettingsMap(pg)
	if err != nil {
		if runErr == "" {
			runErr = err.Error()
		}
		return features, runErr
	}
	embedGucSettingsInFileData(fileData, settings, startedAt, finishedAt)
	if len(features) == 0 || !slices.Contains(features, cons.RootCMD_GucDrift) {
		features = append(features, cons.RootCMD_GucDrift)
	}
	return features, runErr
}
