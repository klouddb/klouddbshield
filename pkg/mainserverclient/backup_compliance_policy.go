package mainserverclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/backupcompliance"
)

// BackupCompliancePolicyResponse matches GET /api/backup-compliance/policy.
type BackupCompliancePolicyResponse struct {
	AllowedStart string   `json:"allowed_start"`
	AllowedEnd   string   `json:"allowed_end"`
	AllowedDays  []string `json:"allowed_days"`
	Timezone     string   `json:"timezone,omitempty"`
	Configured   bool     `json:"configured"`
}

// GetBackupCompliancePolicy fetches the dashboard-saved window from main-server.
func (c *Client) GetBackupCompliancePolicy(ctx context.Context) (backupcompliance.Policy, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/backup-compliance/policy", nil)
	if err != nil {
		return backupcompliance.Policy{}, false, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return backupcompliance.Policy{}, false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return backupcompliance.Policy{}, false, fmt.Errorf("GET /api/backup-compliance/policy: HTTP %d (%s)",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out BackupCompliancePolicyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return backupcompliance.Policy{}, false, err
	}
	p := backupcompliance.Policy{
		AllowedStart: strings.TrimSpace(out.AllowedStart),
		AllowedEnd:   strings.TrimSpace(out.AllowedEnd),
		Timezone:     strings.TrimSpace(out.Timezone),
	}
	for _, d := range out.AllowedDays {
		d = strings.TrimSpace(d)
		if d != "" {
			p.AllowedDays = append(p.AllowedDays, d)
		}
	}
	return p, out.Configured || backupcompliance.PolicyConfigured(p), nil
}
