package main

import (
	"context"
	"sync"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/mainserverclient"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/rs/zerolog/log"
)

type cronPushState struct {
	mu            sync.RWMutex
	scheduledJobs int
	cronRunning   bool
	lastError     string
	mainClient    *mainserverclient.Client
}

func (c *cronHelper) pushState() *cronPushState {
	if c.push == nil {
		c.push = &cronPushState{}
	}
	return c.push
}

func (c *cronHelper) setScheduledJobCount(n int) {
	if !c.cnf.MainServer.Enabled {
		return
	}
	st := c.pushState()
	st.mu.Lock()
	st.scheduledJobs = n
	st.mu.Unlock()
}

func (c *cronHelper) startMainServerPush() {
	st := c.pushState()
	if st.mainClient != nil {
		return
	}
	client, err := mainserverclient.New(c.cnf)
	if err != nil {
		log.Warn().Err(err).Msg("main server push disabled")
		return
	}
	st.mainClient = client
	client.StartRetryFlusher(c.ctx)

	st.mu.RLock()
	jobs := st.scheduledJobs
	st.mu.RUnlock()
	if err := client.PushRegister(c.ctx, mainserverclient.RegisterPayload{
		Schedule:      c.cnf.Collector.Schedule,
		ScanCommands:  c.cnf.Collector.ScanCommands,
		ScheduledJobs: jobs,
	}); err != nil {
		log.Warn().Err(err).Msg("main server register failed")
		_ = client.PushLog(c.ctx, mainserverclient.LogPayload{
			Level:   "error",
			Message: "register failed: " + err.Error(),
		})
	} else {
		_ = client.PushActivity(c.ctx, mainserverclient.ActivityPayload{
			Kind:    "register",
			Message: "collector registered with main server",
			Level:   "info",
		})
	}
	c.pushHeartbeatOnce()

	interval := c.cnf.MainServer.EffectivePushInterval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.pushHeartbeatOnce()
			}
		}
	}()
}

func (c *cronHelper) pushHeartbeatOnce() {
	client := c.pushClient()
	if client == nil {
		return
	}
	st := c.pushState()
	st.mu.RLock()
	jobs := st.scheduledJobs
	running := st.cronRunning
	lastErr := st.lastError
	if client.AuthBlocked() {
		lastErr = "invalid token"
	}
	st.mu.RUnlock()
	if err := client.PushHeartbeat(c.ctx, mainserverclient.HeartbeatPayload{
		CronRunning:   running,
		ScheduledJobs: jobs,
		LastError:     lastErr,
	}); err != nil {
		log.Warn().Err(err).Msg("main server heartbeat failed")
		_ = client.PushLog(c.ctx, mainserverclient.LogPayload{
			Level:   "error",
			Message: "heartbeat failed: " + err.Error(),
		})
	}
}

func (c *cronHelper) recordCronRunError(msg string) {
	if !c.cnf.MainServer.Enabled {
		return
	}
	st := c.pushState()
	st.mu.Lock()
	st.lastError = msg
	st.mu.Unlock()
}

func (c *cronHelper) pushClient() *mainserverclient.Client {
	if !c.cnf.MainServer.Enabled {
		return nil
	}
	st := c.pushState()
	st.mu.RLock()
	client := st.mainClient
	st.mu.RUnlock()
	return client
}

func (c *cronHelper) markCronRunning(running bool) {
	if !c.cnf.MainServer.Enabled {
		return
	}
	st := c.pushState()
	st.mu.Lock()
	st.cronRunning = running
	st.mu.Unlock()
}

func (c *cronHelper) pushCronRunFinishWithClient(client *mainserverclient.Client, started time.Time, features []string, runErr string) {
	if client == nil {
		return
	}
	ctx := context.Background()
	finished := time.Now().UTC()
	success := runErr == ""
	if pending := client.FlushRetries(ctx); pending > 0 && success {
		success = false
		if runErr == "" {
			runErr = "main-server unreachable; scan data pending retry"
		}
	}
	durationMs := finished.Sub(started).Milliseconds()
	if durationMs < 0 {
		durationMs = 0
	}
	_ = client.PushRun(ctx, mainserverclient.RunPayload{
		Trigger:    "cron",
		StartedAt:  started,
		FinishedAt: finished,
		DurationMs: durationMs,
		Features:   append([]string(nil), features...),
		Success:    success,
		Error:      runErr,
	})
	_ = client.PushActivity(ctx, mainserverclient.ActivityPayload{
		Kind:    "cron_tick",
		Message: "cron tick finished",
		Level:   "info",
	})
}

// pushMainServerTickResults embeds SHOW ALL in the scan payload and pushes with scan data.
func pushMainServerTickResults(
	cnf *config.Config,
	client *mainserverclient.Client,
	fileData map[string]interface{},
	startedAt, finishedAt time.Time,
	pg *postgresdb.Postgres,
	trigger string,
	features []string,
	runErr string,
) ([]string, string) {
	if cnf == nil || client == nil || !cnf.MainServer.Enabled {
		return features, runErr
	}
	features, runErr = collectGucIntoScanPayload(cnf, pg, fileData, startedAt, finishedAt, features, runErr)
	collectLogReadinessIntoScanPayload(cnf, pg, fileData, startedAt, finishedAt)
	if len(fileData) > 0 {
		pushScanDataToMainServer(cnf, client, fileData, startedAt, finishedAt, pg, trigger, features, runErr)
	}
	return features, runErr
}

// pushScanDataToMainServer posts CIS/HBA scan JSON to /api/collector/data.
func pushScanDataToMainServer(
	cnf *config.Config,
	client *mainserverclient.Client,
	fileData map[string]interface{},
	startedAt, finishedAt time.Time,
	pg *postgresdb.Postgres,
	trigger string,
	features []string,
	runErr string,
) {
	if cnf == nil || client == nil || !cnf.MainServer.Enabled {
		return
	}
	payload := mainserverclient.BuildScanPayload(cnf, client, fileData, startedAt, finishedAt, pg, trigger, features, runErr)
	if payload == nil {
		return
	}
	ctx := context.Background()
	if err := client.PushData(ctx, payload); err != nil {
		log.Warn().Err(err).Msg("main server scan data push failed")
		if mainserverclient.IsAuthError(err) {
			return
		}
	}
	_ = client.FlushRetries(ctx)
	_ = client.PushActivity(ctx, mainserverclient.ActivityPayload{
		Kind:    "scan_data",
		Message: "scan results pushed to main server",
		Level:   "info",
	})
}
