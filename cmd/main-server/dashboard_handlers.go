package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	dashboardsvc "github.com/klouddb/klouddbshield/pkg/dashboard/service"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func (a *App) dashboardSvc() *dashboardsvc.Service {
	if a.DashboardSvc == nil {
		return nil
	}
	return a.DashboardSvc
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) hostsHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.HostsResponse{Rows: [][]string{}})
		return
	}
	resp, err := svc.Hosts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) violationsHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.CriticalChecksResponse{Checks: []dashboardsvc.CriticalCheckDef{}})
		return
	}
	resp, err := svc.CriticalChecksFleet(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) criticalChecksHandler(w http.ResponseWriter, r *http.Request) {
	a.violationsHandler(w, r)
}

func (a *App) runsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.RunsResponse{Runs: []dashboardsvc.RunSummary{}})
		return
	}
	resp, err := svc.Runs(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) strategicHandler(w http.ResponseWriter, r *http.Request) {
	rangeKey := r.URL.Query().Get("range")
	if rangeKey == "" {
		rangeKey = "30d"
	}
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.StrategicResponse{
			Ranges: map[string]dashboardsvc.StrategicRange{
				"30d": {Label: "Last 30 days", Health: 0, Grade: "-", Servers: 0},
			},
		})
		return
	}
	resp, err := svc.Strategic(r.Context(), rangeKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) fleetCategoriesHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.FleetCategoriesResponse{Categories: []dashboardsvc.FleetCategory{}})
		return
	}
	resp, err := svc.FleetCategories(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucDriftHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.GucDriftResponse{})
		return
	}
	groupID := strings.TrimSpace(r.URL.Query().Get("group_id"))
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	var (
		resp *dashboardsvc.GucDriftResponse
		err  error
	)
	if groupID != "" || targetID != "" {
		resp, err = svc.GucDriftQuery(r.Context(), groupID, targetID)
	} else {
		resp, err = svc.GucDrift(r.Context())
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucBaselineGetHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.GucBaselineResponse{Settings: map[string]string{}})
		return
	}
	groupID := strings.TrimSpace(r.URL.Query().Get("group_id"))
	resp, err := svc.GucBaselineForGroup(r.Context(), groupID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucBaselinePutHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Label    string            `json:"label"`
		TargetID string            `json:"target_id"`
		GroupID  string            `json:"group_id"`
		Settings map[string]string `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	groupID := strings.TrimSpace(req.GroupID)
	var err error
	if groupID != "" {
		if strings.TrimSpace(req.TargetID) != "" {
			err = svc.PutGucGroupBaselineFromHost(r.Context(), groupID, req.TargetID)
		} else if req.Settings != nil {
			err = svc.PutGucGroupBaselineFile(r.Context(), groupID, req.Label, req.Settings)
		} else {
			http.Error(w, "target_id or settings is required", http.StatusBadRequest)
			return
		}
	} else if strings.TrimSpace(req.TargetID) != "" {
		err = svc.PutGucBaselineFromHost(r.Context(), req.TargetID)
	} else if req.Settings != nil {
		err = svc.PutGucBaseline(r.Context(), req.Label, req.Settings)
	} else {
		http.Error(w, "target_id or settings is required", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := svc.GucBaselineForGroup(r.Context(), groupID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucSnapshotsHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.GucSnapshotsResponse{Snapshots: []dashboardsvc.GucSnapshotEntry{}})
		return
	}
	resp, err := svc.GucSnapshots(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucIgnoresGetHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.GucIgnoresResponse{Ignores: []dashboardsvc.GucIgnoreEntryDTO{}})
		return
	}
	resp, err := svc.ListGucIgnores(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucIgnoresPutHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Scope    string `json:"scope"`
		TargetID string `json:"target_id"`
		Guc      string `json:"guc"`
		Ignore   *bool  `json:"ignore"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ignore := true
	if req.Ignore != nil {
		ignore = *req.Ignore
	}
	if err := svc.SetGucIgnore(r.Context(), req.Scope, req.TargetID, req.Guc, ignore); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := svc.ListGucIgnores(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucGroupsGetHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.GucServerGroupsResponse{Groups: []dashboardsvc.GucServerGroupDTO{}})
		return
	}
	resp, err := svc.ListGucServerGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) gucGroupsPostHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	dto, err := svc.UpsertGucServerGroup(r.Context(), req.ID, req.Name, req.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (a *App) gucGroupDeleteHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["groupId"])
	if id == "" {
		http.Error(w, "group id required", http.StatusBadRequest)
		return
	}
	if err := svc.DeleteGucServerGroup(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *App) gucGroupMembersPutHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(mux.Vars(r)["groupId"])
	if id == "" {
		http.Error(w, "group id required", http.StatusBadRequest)
		return
	}
	var req struct {
		TargetIDs []string `json:"target_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := svc.SetGucServerGroupMembers(r.Context(), id, req.TargetIDs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dto, err := svc.GetGucServerGroup(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (a *App) policiesHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.PoliciesResponse{})
		return
	}
	resp, err := svc.Policies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) collectorConfigHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.CollectorConfigResponse{})
		return
	}
	resp, err := svc.CollectorConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) runHTMLHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	runID := vars["runId"]
	if a.Repo == nil {
		http.Error(w, "report database not configured", http.StatusServiceUnavailable)
		return
	}
	row, err := a.Repo.GetRunByID(r.Context(), runID)
	if err != nil || row == nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if path := os.Getenv("KSHIELD_HTML_REPORT"); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.URL.Query().Get("download") == "1" {
				w.Header().Set("Content-Disposition", "attachment; filename=klouddbshield_report.html")
			}
			_, _ = w.Write(b)
			return
		}
	}
	title := hostLabelForExport(row)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-report.html", title))
	}
	_, _ = w.Write([]byte(dashboardsvc.RenderRunHTML(r.Context(), a.Repo, row)))
}

func hostLabelForExport(row *reportstore.RunRow) string {
	if row.TargetHost != "" {
		return row.TargetHost
	}
	return row.TargetID
}

func (a *App) hbaScannerHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.HbaScannerResponse{Host: host})
		return
	}
	resp, err := svc.HbaScanner(r.Context(), host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) sslScannerHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.SslScannerResponse{Host: host})
		return
	}
	resp, err := svc.SslScanner(r.Context(), host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) piiScannerHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.PiiScannerResponse{Host: host})
		return
	}
	resp, err := svc.PiiScanner(r.Context(), host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) backupComplianceSummaryHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.BackupComplianceSummaryResponse{})
		return
	}
	resp, err := svc.BackupComplianceSummary(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) backupComplianceHistoryHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.BackupComplianceHistoryResponse{})
		return
	}
	f := dashboardsvc.BackupComplianceHistoryFilter{
		Server:     r.URL.Query().Get("server"),
		BackupType: r.URL.Query().Get("backup_type"),
		Date:       r.URL.Query().Get("date"),
		From:       r.URL.Query().Get("from"),
		To:         r.URL.Query().Get("to"),
		Status:     r.URL.Query().Get("status"),
	}
	resp, err := svc.BackupComplianceHistory(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) backupCompliancePolicyGetHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.BackupCompliancePolicyResponse{
			AllowedDays: []string{},
			Source:      "none",
			Hint:        "Database not configured",
		})
		return
	}
	resp, err := svc.GetBackupCompliancePolicy(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) backupCompliancePolicyPutHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	var req dashboardsvc.BackupCompliancePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	resp, err := svc.PutBackupCompliancePolicy(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) logParserScannerHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.LogParserScannerResponse{Host: host})
		return
	}
	resp, err := svc.LogParserScanner(r.Context(), host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) logReadinessHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.LogReadinessFleetResponse{Rows: []dashboardsvc.LogReadinessHostRow{}})
		return
	}
	resp, err := svc.LogReadinessFleet(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) inactiveUsersReportHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.InactiveUsersReportResponse{Rows: []dashboardsvc.InactiveUserReportRow{}})
		return
	}
	resp, err := svc.InactiveUsersReport(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) commonUsersReportHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, dashboardsvc.CommonUsersReportResponse{Rows: []dashboardsvc.CommonUserReportRow{}})
		return
	}
	resp, err := svc.CommonUsersReport(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) overviewHandler(w http.ResponseWriter, r *http.Request) {
	svc := a.dashboardSvc()
	if svc == nil {
		writeJSON(w, http.StatusOK, OverviewResponse{
			Summary:   Summary{},
			UpdatedAt: time.Now(),
		})
		return
	}
	dash, err := svc.Overview(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := OverviewResponse{
		Summary: Summary{
			Servers:  dash.Summary.Servers,
			Healthy:  dash.Summary.Healthy,
			Warning:  dash.Summary.Warning,
			Critical: dash.Summary.Critical,
		},
		UpdatedAt: dash.UpdatedAt,
	}
	if len(dash.Servers) > 0 {
		resp.CentralServer = Server{
			ID:     dash.CentralServer.ID,
			Name:   dash.CentralServer.Name,
			IP:     dash.CentralServer.IP,
			Status: dash.CentralServer.Status,
			ServerSummary: ServerSummary{
				TotalCases:  dash.CentralServer.ServerSummary.TotalCases,
				PassedCases: dash.CentralServer.ServerSummary.PassedCases,
			},
		}
		for _, s := range dash.Servers {
			resp.Servers = append(resp.Servers, Server{
				ID:     s.ID,
				Name:   s.Name,
				IP:     s.IP,
				Status: s.Status,
				ServerSummary: ServerSummary{
					TotalCases:  s.ServerSummary.TotalCases,
					PassedCases: s.ServerSummary.PassedCases,
				},
			})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) serverHandler(w http.ResponseWriter, r *http.Request) {
	hostQ := strings.TrimSpace(r.URL.Query().Get("host"))
	instanceQ := strings.TrimSpace(r.URL.Query().Get("instance"))
	serverID := hostQ
	if serverID == "" {
		serverID = instanceQ
	}
	if serverID == "" {
		serverID = strings.TrimSpace(mux.Vars(r)["serverId"])
	}
	svc := a.dashboardSvc()
	if svc == nil {
		http.Error(w, "report database not available", http.StatusServiceUnavailable)
		return
	}

	wantOverview := instanceQ != ""
	parsed := dashboardsvc.ParseHostKey(serverID)
	if !wantOverview && parsed.Database == "" && serverID != "" {
		wantOverview = true
	}

	if wantOverview {
		inst := instanceQ
		if inst == "" {
			inst = parsed.Instance
		}
		overview, err := svc.HostInstanceOverview(r.Context(), inst)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if overview == nil {
			http.Error(w, "server not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, overview)
		return
	}

	reportKey := parsed.HostKey
	if reportKey == "" {
		reportKey = serverID
	}
	detail, err := svc.HostReport(r.Context(), reportKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if detail == nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}
