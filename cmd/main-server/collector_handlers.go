package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const collectorSchemaVersion = "v1"

type collectorHeartbeatRequest struct {
	SchemaVersion string    `json:"schema_version"`
	NodeID        string    `json:"node_id"`
	Hostname      string    `json:"hostname"`
	IP            string    `json:"ip,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Status        struct {
		CronRunning   bool   `json:"cron_running"`
		ScheduledJobs int    `json:"scheduled_jobs"`
		LastError     string `json:"last_error"`
	} `json:"status"`
}

type collectorActivityRequest struct {
	SchemaVersion string    `json:"schema_version"`
	NodeID        string    `json:"node_id"`
	Hostname      string    `json:"hostname"`
	Timestamp     time.Time `json:"timestamp"`
	Activity      struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"activity"`
}

type collectorLogRequest struct {
	SchemaVersion string    `json:"schema_version"`
	NodeID        string    `json:"node_id"`
	Hostname      string    `json:"hostname"`
	Timestamp     time.Time `json:"timestamp"`
	Log           struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"log"`
}

type collectorRunRequest struct {
	SchemaVersion string `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Hostname      string `json:"hostname"`
	Run           struct {
		Trigger    string    `json:"trigger"`
		StartedAt  time.Time `json:"started_at"`
		FinishedAt time.Time `json:"finished_at"`
		Features   []string  `json:"features"`
		Success    bool      `json:"success"`
		Error      string    `json:"error"`
	} `json:"run"`
}

type CollectorNodeView struct {
	NodeID        string     `json:"node_id"`
	Hostname      string     `json:"hostname"`
	IP            string     `json:"ip,omitempty"`
	Status        string     `json:"status"`
	CronRunning   bool       `json:"cron_running"`
	ScheduledJobs int        `json:"scheduled_jobs"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

func (a *App) collectorHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	var req collectorHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != collectorSchemaVersion {
		http.Error(w, "unsupported schema", http.StatusBadRequest)
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	hostname := strings.TrimSpace(req.Hostname)
	if nodeID == "" || hostname == "" {
		http.Error(w, "node_id and hostname required", http.StatusBadRequest)
		return
	}
	ts := req.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	if err := a.Svc.CollectorHeartbeat(ctx, nodeID, hostname, req.IP, ts,
		req.Status.CronRunning, req.Status.ScheduledJobs, req.Status.LastError); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *App) collectorActivityHandler(w http.ResponseWriter, r *http.Request) {
	var req collectorActivityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != collectorSchemaVersion {
		http.Error(w, "unsupported schema", http.StatusBadRequest)
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	ts := req.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if err := a.Svc.RecordCollectorActivity(ctx, nodeID,
		strings.TrimSpace(req.Activity.Kind), req.Activity.Message,
		strings.TrimSpace(req.Activity.Level), ts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *App) collectorLogsHandler(w http.ResponseWriter, r *http.Request) {
	var req collectorLogRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != collectorSchemaVersion {
		http.Error(w, "unsupported schema", http.StatusBadRequest)
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	ts := req.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if err := a.Svc.RecordCollectorLog(ctx, nodeID,
		strings.TrimSpace(req.Log.Level), req.Log.Message, ts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *App) collectorRunsHandler(w http.ResponseWriter, r *http.Request) {
	var req collectorRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != collectorSchemaVersion {
		http.Error(w, "unsupported schema", http.StatusBadRequest)
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	hostname := strings.TrimSpace(req.Hostname)
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	finished := req.Run.FinishedAt
	if finished.IsZero() {
		finished = time.Now().UTC()
	}
	if err := a.Svc.RecordCollectorRun(ctx, nodeID, hostname,
		strings.TrimSpace(req.Run.Trigger), req.Run.StartedAt, finished,
		req.Run.Features, req.Run.Success, strings.TrimSpace(req.Run.Error)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *App) collectorNodesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	threshold := a.collectorOfflineThreshold()
	rows, err := a.Svc.ListCollectorNodes(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var out []CollectorNodeView
	for _, row := range rows {
		out = append(out, collectorNodeViewFromRow(row, threshold))
	}
	if out == nil {
		out = []CollectorNodeView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":                 out,
		"updated_at":            time.Now().UTC(),
		"offline_threshold_sec": int(threshold.Seconds()),
		"push_interval_sec":     a.collectorPushIntervalSec(),
	})
}

func (a *App) collectorNodeHandler(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(mux.Vars(r)["id"])
	if nodeID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	row, err := a.Svc.GetCollectorNode(ctx, nodeID)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, collectorNodeViewFromRow(*row, a.collectorOfflineThreshold()))
}

func (a *App) collectorNodeRunsHandler(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(mux.Vars(r)["id"])
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	runs, err := a.Svc.ListCollectorRuns(ctx, nodeID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type runRow struct {
		ID         int64      `json:"id"`
		Trigger    string     `json:"trigger"`
		StartedAt  time.Time  `json:"started_at"`
		FinishedAt *time.Time `json:"finished_at,omitempty"`
		DurationMs int64      `json:"duration_ms"`
		Features   []string   `json:"features,omitempty"`
		Success    bool       `json:"success"`
		Error      string     `json:"error,omitempty"`
	}
	var out []runRow
	for _, run := range runs {
		var durationMs int64
		if run.FinishedAt != nil && !run.FinishedAt.IsZero() && !run.StartedAt.IsZero() {
			durationMs = run.FinishedAt.Sub(run.StartedAt).Milliseconds()
			if durationMs < 0 {
				durationMs = 0
			}
		}
		out = append(out, runRow{
			ID:         run.ID,
			Trigger:    run.Trigger,
			StartedAt:  run.StartedAt,
			FinishedAt: run.FinishedAt,
			DurationMs: durationMs,
			Features:   run.Features,
			Success:    run.Success,
			Error:      run.Error,
		})
	}
	if out == nil {
		out = []runRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

func (a *App) collectorNodeActivityHandler(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(mux.Vars(r)["id"])
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	items, err := a.Svc.ListCollectorActivity(ctx, nodeID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type act struct {
		Kind      string    `json:"kind"`
		Message   string    `json:"message"`
		Level     string    `json:"level,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}
	var out []act
	for _, item := range items {
		out = append(out, act{
			Kind: item.Kind, Message: item.Message, Level: item.Level, CreatedAt: item.CreatedAt,
		})
	}
	if out == nil {
		out = []act{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"activity": out})
}

func (a *App) collectorNodeLogsHandler(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(mux.Vars(r)["id"])
	if nodeID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := requireService(a); err != nil {
		http.Error(w, "main database not initialized", http.StatusInternalServerError)
		return
	}

	items, err := a.Svc.ListCollectorLogs(ctx, nodeID, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type logRow struct {
		Level     string    `json:"level"`
		Message   string    `json:"message"`
		CreatedAt time.Time `json:"created_at"`
	}
	var out []logRow
	for _, item := range items {
		out = append(out, logRow{Level: item.Level, Message: item.Message, CreatedAt: item.CreatedAt})
	}
	if out == nil {
		out = []logRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out})
}
