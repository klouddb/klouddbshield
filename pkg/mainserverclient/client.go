package mainserverclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/collectoridentity"
	"github.com/klouddb/klouddbshield/pkg/config"
)

// Client pushes collector status and run data to the main-server.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	nodeID     string
	hostname   string
	retry      *RetryQueue
}

// New builds a client from collector config.
func New(cnf *config.Config) (*Client, error) {
	ms := cnf.MainServer
	if !ms.Enabled {
		return nil, fmt.Errorf("mainserver is not enabled")
	}
	url := strings.TrimRight(strings.TrimSpace(ms.URL), "/")
	if url == "" {
		return nil, fmt.Errorf("mainserver.url is empty")
	}
	host := strings.TrimSpace(cnf.App.Hostname)
	if host == "" {
		return nil, fmt.Errorf("app.hostname is required for main server push")
	}
	id, err := collectoridentity.LoadOrCreate(host)
	if err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(ms)
	if err != nil {
		return nil, err
	}
	c := &Client{
		baseURL:    url,
		token:      strings.TrimSpace(ms.Token),
		httpClient: httpClient,
		nodeID:     id.NodeID,
		hostname:   host,
	}
	c.retry = newRetryQueue(c.postDirect)
	return c, nil
}

// StartRetryFlusher begins background retry processing.
func (c *Client) StartRetryFlusher(ctx context.Context) {
	if c.retry != nil {
		c.retry.StartFlusher(ctx)
	}
}

// FlushRetries attempts pending queued posts.
func (c *Client) FlushRetries(ctx context.Context) int {
	if c.retry == nil {
		return 0
	}
	return c.retry.Flush(ctx)
}

// AuthBlocked is true after a 401 response.
func (c *Client) AuthBlocked() bool {
	if c.retry == nil {
		return false
	}
	return c.retry.AuthBlocked()
}

// BaseURL returns the configured main-server URL.
func (c *Client) BaseURL() string { return c.baseURL }

// NodeID returns the stable collector node identifier.
func (c *Client) NodeID() string { return c.nodeID }

// Hostname returns the configured collector hostname.
func (c *Client) Hostname() string { return c.hostname }

// HeartbeatPayload is sent on each heartbeat tick.
type HeartbeatPayload struct {
	CronRunning   bool   `json:"cron_running"`
	ScheduledJobs int    `json:"scheduled_jobs"`
	LastError     string `json:"last_error,omitempty"`
}

type heartbeatRequest struct {
	SchemaVersion string           `json:"schema_version"`
	NodeID        string           `json:"node_id"`
	Hostname      string           `json:"hostname"`
	Timestamp     time.Time        `json:"timestamp"`
	Status        HeartbeatPayload `json:"status"`
}

// RegisterPayload is sent once when the collector agent starts cron mode.
type RegisterPayload struct {
	Schedule      string `json:"schedule,omitempty"`
	ScanCommands  string `json:"scan_commands,omitempty"`
	ScheduledJobs int    `json:"scheduled_jobs"`
}

type registerRequest struct {
	SchemaVersion string    `json:"schema_version"`
	NodeID        string    `json:"node_id"`
	Hostname      string    `json:"hostname"`
	IP            string    `json:"ip,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Schedule      string    `json:"schedule,omitempty"`
	ScanCommands  string    `json:"scan_commands,omitempty"`
	ScheduledJobs int       `json:"scheduled_jobs"`
}

// PushRegister announces this collector to the main-server fleet (also stored in collector_status).
func (c *Client) PushRegister(ctx context.Context, reg RegisterPayload) error {
	body := registerRequest{
		SchemaVersion: "v1",
		NodeID:        c.nodeID,
		Hostname:      c.hostname,
		Timestamp:     time.Now().UTC(),
		Schedule:      strings.TrimSpace(reg.Schedule),
		ScanCommands:  strings.TrimSpace(reg.ScanCommands),
		ScheduledJobs: reg.ScheduledJobs,
	}
	return c.send(ctx, "/api/collector/register", body)
}

// PushHeartbeat updates collector_status on the main-server.
func (c *Client) PushHeartbeat(ctx context.Context, st HeartbeatPayload) error {
	body := heartbeatRequest{
		SchemaVersion: "v1",
		NodeID:        c.nodeID,
		Hostname:      c.hostname,
		Timestamp:     time.Now().UTC(),
		Status:        st,
	}
	return c.send(ctx, "/api/collector/heartbeat", body)
}

// ActivityPayload records a single operational event.
type ActivityPayload struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Level   string `json:"level,omitempty"`
}

type activityRequest struct {
	SchemaVersion string          `json:"schema_version"`
	NodeID        string          `json:"node_id"`
	Hostname      string          `json:"hostname"`
	Timestamp     time.Time       `json:"timestamp"`
	Activity      ActivityPayload `json:"activity"`
}

// PushActivity appends an activity row.
func (c *Client) PushActivity(ctx context.Context, act ActivityPayload) error {
	body := activityRequest{
		SchemaVersion: "v1",
		NodeID:        c.nodeID,
		Hostname:      c.hostname,
		Timestamp:     time.Now().UTC(),
		Activity:      act,
	}
	return c.send(ctx, "/api/collector/activity", body)
}

// RunPayload describes one cron or manual execution.
type RunPayload struct {
	Trigger    string    `json:"trigger"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	Features   []string  `json:"features,omitempty"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
}

type runRequest struct {
	SchemaVersion string     `json:"schema_version"`
	NodeID        string     `json:"node_id"`
	Hostname      string     `json:"hostname"`
	Run           RunPayload `json:"run"`
}

// PushRun records execution history.
func (c *Client) PushRun(ctx context.Context, run RunPayload) error {
	body := runRequest{
		SchemaVersion: "v1",
		NodeID:        c.nodeID,
		Hostname:      c.hostname,
		Run:           run,
	}
	return c.send(ctx, "/api/collector/runs", body)
}

// LogPayload is one log line pushed to the main-server.
type LogPayload struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type logRequest struct {
	SchemaVersion string     `json:"schema_version"`
	NodeID        string     `json:"node_id"`
	Hostname      string     `json:"hostname"`
	Timestamp     time.Time  `json:"timestamp"`
	Log           LogPayload `json:"log"`
}

// PushLog stores a log line.
func (c *Client) PushLog(ctx context.Context, line LogPayload) error {
	body := logRequest{
		SchemaVersion: "v1",
		NodeID:        c.nodeID,
		Hostname:      c.hostname,
		Timestamp:     time.Now().UTC(),
		Log:           line,
	}
	return c.send(ctx, "/api/collector/logs", body)
}

// PushData posts a full scan payload to /api/collector/data.
func (c *Client) PushData(ctx context.Context, payload any) error {
	return c.send(ctx, "/api/collector/data", payload)
}

func (c *Client) send(ctx context.Context, path string, body any) error {
	if c.AuthBlocked() {
		return &APIError{Path: path, StatusCode: 401, Message: "auth blocked"}
	}
	err := c.postDirect(ctx, path, body)
	if err == nil {
		return nil
	}
	if IsAuthError(err) {
		c.retry.SetAuthBlocked(true)
		return err
	}
	if IsRetryable(err) && c.retry != nil {
		c.retry.Enqueue(path, body)
	}
	return err
}

func (c *Client) postDirect(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &APIError{
			Path:       path,
			StatusCode: resp.StatusCode,
			Message:    strings.TrimSpace(string(msg)),
		}
	}
	return nil
}
