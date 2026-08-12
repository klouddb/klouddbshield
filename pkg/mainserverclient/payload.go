package mainserverclient

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

// NodePayload matches the legacy main-server /api/collector/data schema.
type NodePayload struct {
	SchemaVersion string    `json:"schema_version"`
	Node          NodeInfo  `json:"node"`
	Timestamp     time.Time `json:"timestamp"`
	Data          NodeData  `json:"data"`
}

type NodeInfo struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	IP          string      `json:"ip"`
	AgentConfig AgentConfig `json:"agent_config"`
}

type NodeData struct {
	PostgresCIS                 *PostgresCISPayload          `json:"postgres_cis,omitempty"`
	HBAScanResult               *HBAScannerPayload           `json:"hba_scan_result,omitempty"`
	LogParserMetadataSuggestion *LogParserMetadataSuggestion `json:"log_parser_metadata_suggestion,omitempty"`
	GucSettings                 *GucSettingsPayload          `json:"guc_settings,omitempty"`
}

// GucSettingsPayload is pg_settings output pushed for GUC drift comparison
// (setting values plus packed unit/vartype metadata in reserved keys).
type GucSettingsPayload struct {
	Settings map[string]string `json:"settings"`
	ScanMeta ScanMetadata      `json:"scan_meta"`
}

type PostgresCISPayload struct {
	Version  string                 `json:"version"`
	Summary  map[int]interface{}    `json:"summary"`
	Errors   map[string]string      `json:"errors,omitempty"`
	Reports  map[string]interface{} `json:"reports"`
	ScanMeta ScanMetadata           `json:"scan_meta"`
}

type HBAScannerPayload struct {
	Version  string                 `json:"version"`
	Result   []HBAScannerResult     `json:"hbascannerresult"`
	Errors   map[string]string      `json:"errors,omitempty"`
	Reports  map[string]interface{} `json:"reports"`
	ScanMeta ScanMetadata           `json:"scan_meta"`
}

type HBAScannerResult struct {
	Title            string   `json:"title"`
	Control          int      `json:"control"`
	Description      string   `json:"description"`
	Procedure        string   `json:"procedure"`
	Status           string   `json:"status"`
	FailRowsLineNums []int    `json:"failrowlinenums,omitempty"`
	FailRows         []string `json:"FailRows,omitempty"`
	FailRowsInString string   `json:"failowsinstring,omitempty"`
}

type LogParserMetadataSuggestion struct {
	ID            string       `json:"id"`
	LogFilePrefix string       `json:"log_file_prefix,omitempty"`
	DataDirectory string       `json:"data_directory,omitempty"`
	PGUsers       []string     `json:"pg_users,omitempty"`
	HBAFilePath   string       `json:"hba_file_path,omitempty"`
	ScanMeta      ScanMetadata `json:"scan_meta"`
}

type ScanMetadata struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMs int64     `json:"duration_ms"`
}

type AgentConfig struct {
	Agent struct {
		ID string `json:"id"`
	} `json:"agent"`
	Server struct {
		URL   string `json:"url"`
		Token string `json:"token,omitempty"`
	} `json:"server"`
	Node struct {
		Hostname    string `json:"hostname"`
		IP          string `json:"ip"`
		Environment string `json:"environment"`
		Role        string `json:"role"`
	} `json:"node"`
}

// ScanRunMeta is scan execution metadata sent with /api/collector/data.
type ScanRunMeta struct {
	Trigger      string    `json:"trigger"`
	Features     []string  `json:"features,omitempty"`
	TargetID     string    `json:"target_id"`
	TargetHost   string    `json:"target_host"`
	TargetPort   string    `json:"target_port"`
	TargetDB     string    `json:"target_db"`
	RunStatus    string    `json:"run_status"`
	ErrorMessage string    `json:"error_message,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
}

// ScanDataRequest is the v2 collector data payload.
type ScanDataRequest struct {
	SchemaVersion string                 `json:"schema_version"`
	Node          NodeInfo               `json:"node"`
	Timestamp     time.Time              `json:"timestamp"`
	Data          NodeData               `json:"data"`
	ScanRun       ScanRunMeta            `json:"scan_run"`
	Report        map[string]interface{} `json:"report"`
}

// BuildScanPayload converts collector fileData for /api/collector/data.
func BuildScanPayload(
	cnf *config.Config,
	c *Client,
	fileData map[string]interface{},
	startedAt, finishedAt time.Time,
	pg *postgresdb.Postgres,
	trigger string,
	features []string,
	runErr string,
) *ScanDataRequest {
	node := BuildNodePayload(cnf, c, fileData, startedAt, finishedAt)
	if node == nil {
		return nil
	}
	if pg == nil {
		pg = cnf.Postgres
	}
	host, port, dbName := "", "", ""
	tid := reportstore.TargetID(pg)
	if pg != nil {
		host = reportstore.ResolveTargetHost(pg.Host, c.Hostname())
		port = pg.Port
		if port == "" {
			port = "5432"
		}
		dbName = pg.DBName
		// Rebuild target id with resolved host so loopback configs stay unique per agent.
		pgResolved := *pg
		pgResolved.Host = host
		tid = reportstore.TargetID(&pgResolved)
	}
	status := "success"
	if runErr != "" {
		status = "failed"
	}
	report := map[string]interface{}{}
	for k, v := range fileData {
		report[k] = v
	}
	return &ScanDataRequest{
		SchemaVersion: "v1",
		Node:          node.Node,
		Timestamp:     node.Timestamp,
		Data:          node.Data,
		Report:        report,
		ScanRun: ScanRunMeta{
			Trigger:      trigger,
			Features:     append([]string(nil), features...),
			TargetID:     tid,
			TargetHost:   host,
			TargetPort:   port,
			TargetDB:     dbName,
			RunStatus:    status,
			ErrorMessage: runErr,
			StartedAt:    startedAt.UTC(),
			FinishedAt:   finishedAt.UTC(),
		},
	}
}

// BuildNodePayload converts collector fileData into the main-server NodePayload shape.
// Returns nil when there is no pushable CIS/HBA scan content.
func BuildNodePayload(cnf *config.Config, c *Client, fileData map[string]interface{}, startedAt, finishedAt time.Time) *NodePayload {
	if c == nil || cnf == nil || len(fileData) == 0 {
		return nil
	}
	durationMs := finishedAt.Sub(startedAt).Milliseconds()
	if durationMs < 0 {
		durationMs = 0
	}
	meta := ScanMetadata{
		StartedAt:  startedAt.UTC(),
		FinishedAt: finishedAt.UTC(),
		DurationMs: durationMs,
	}

	data := NodeData{}
	if cis := buildPostgresCISPayload(fileData, meta); cis != nil {
		data.PostgresCIS = cis
	}
	if hba := buildHBAScanPayload(fileData, meta); hba != nil {
		data.HBAScanResult = hba
	}
	if lp := buildLogParserMetadata(cnf, c, meta); lp != nil {
		data.LogParserMetadataSuggestion = lp
	}
	if guc := buildGucSettingsPayload(fileData, meta); guc != nil {
		data.GucSettings = guc
	}
	if data.PostgresCIS == nil && data.HBAScanResult == nil && data.LogParserMetadataSuggestion == nil && data.GucSettings == nil {
		return nil
	}

	ip := nodeIP(cnf)
	payload := &NodePayload{
		SchemaVersion: "v1",
		Timestamp:     finishedAt.UTC(),
		Node: NodeInfo{
			ID:   c.NodeID(),
			Name: c.Hostname(),
			IP:   ip,
		},
		Data: data,
	}
	payload.Node.AgentConfig.Agent.ID = c.NodeID()
	payload.Node.AgentConfig.Server.URL = strings.TrimRight(strings.TrimSpace(cnf.MainServer.URL), "/")
	payload.Node.AgentConfig.Server.Token = strings.TrimSpace(cnf.MainServer.Token)
	payload.Node.AgentConfig.Node.Hostname = c.Hostname()
	payload.Node.AgentConfig.Node.IP = ip
	return payload
}

func nodeIP(cnf *config.Config) string {
	if cnf == nil || cnf.Postgres == nil {
		return ""
	}
	return strings.TrimSpace(cnf.Postgres.Host)
}

func buildPostgresCISPayload(fileData map[string]interface{}, meta ScanMetadata) *PostgresCISPayload {
	raw, ok := fileData["Postgres Report"]
	if !ok {
		return nil
	}
	report, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	version, _ := report["version"].(string)
	results := decodeCISResults(report["result"])
	if version == "" && len(results) == 0 {
		return nil
	}

	reports := map[string]interface{}{}
	if v, ok := fileData["Postgres Report"]; ok {
		reports["Postgres Report"] = v
	}
	if v, ok := fileData["Users Report"]; ok {
		reports["Users Report"] = v
	}

	return &PostgresCISPayload{
		Version:  version,
		Summary:  cisSummaryFromResults(results),
		Reports:  reports,
		ScanMeta: meta,
	}
}

func buildHBAScanPayload(fileData map[string]interface{}, meta ScanMetadata) *HBAScannerPayload {
	raw, ok := fileData["HBA Report"]
	if !ok {
		return nil
	}
	results := decodeHBAResults(raw)
	if len(results) == 0 {
		return nil
	}
	reports := map[string]interface{}{"HBA Report": raw}
	return &HBAScannerPayload{
		Version:  "v1",
		Result:   results,
		Reports:  reports,
		ScanMeta: meta,
	}
}

func buildGucSettingsPayload(fileData map[string]interface{}, meta ScanMetadata) *GucSettingsPayload {
	raw, ok := fileData["GUC Settings"]
	if !ok {
		return nil
	}
	report, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	settingsRaw, ok := report["settings"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(settingsRaw)
	if err != nil {
		return nil
	}
	settings := map[string]string{}
	if err := json.Unmarshal(b, &settings); err != nil {
		return nil
	}
	if len(settings) == 0 {
		return nil
	}
	gucMeta := meta
	if started, ok := report["started_at"].(time.Time); ok && !started.IsZero() {
		gucMeta.StartedAt = started.UTC()
	}
	if finished, ok := report["finished_at"].(time.Time); ok && !finished.IsZero() {
		gucMeta.FinishedAt = finished.UTC()
		if gucMeta.DurationMs == 0 {
			gucMeta.DurationMs = gucMeta.FinishedAt.Sub(gucMeta.StartedAt).Milliseconds()
		}
	}
	return &GucSettingsPayload{Settings: settings, ScanMeta: gucMeta}
}

func buildLogParserMetadata(cnf *config.Config, c *Client, meta ScanMetadata) *LogParserMetadataSuggestion {
	if cnf == nil || cnf.LogParser == nil {
		return nil
	}
	lp := cnf.LogParser
	hasLogs := len(lp.LogFiles) > 0
	if !hasLogs && strings.TrimSpace(lp.HbaConfFile) == "" {
		return nil
	}
	logPrefix := ""
	if hasLogs {
		logPrefix = lp.LogFiles[0]
	}
	return &LogParserMetadataSuggestion{
		ID:            c.NodeID(),
		LogFilePrefix: logPrefix,
		HBAFilePath:   lp.HbaConfFile,
		ScanMeta:      meta,
	}
}

func decodeCISResults(raw interface{}) []*model.Result {
	if raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var out []*model.Result
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func decodeHBAResults(raw interface{}) []HBAScannerResult {
	if raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var modelRows []model.HBAScannerResult
	if err := json.Unmarshal(b, &modelRows); err != nil {
		return nil
	}
	out := make([]HBAScannerResult, 0, len(modelRows))
	for _, r := range modelRows {
		out = append(out, HBAScannerResult{
			Title:            r.Title,
			Control:          r.Control,
			Description:      r.Description,
			Procedure:        r.Procedure,
			Status:           r.Status,
			FailRowsLineNums: r.FailRowsLineNums,
			FailRows:         r.FailRows,
			FailRowsInString: r.FailRowsInString,
		})
	}
	return out
}

func cisSummaryFromResults(results []*model.Result) map[int]interface{} {
	score := make(map[int]*model.Status)
	for i := 0; i <= 8; i++ {
		score[i] = &model.Status{}
	}
	for _, result := range results {
		if result == nil {
			continue
		}
		controlPrefix := strings.Split(result.Control, ".")[0]
		controlNum, err := strconv.Atoi(controlPrefix)
		if err != nil {
			continue
		}
		if result.Status == "Pass" {
			score[controlNum].Pass++
			score[0].Pass++
		} else if result.Status == "Fail" {
			score[controlNum].Fail++
			score[0].Fail++
		}
	}
	out := make(map[int]interface{}, len(score))
	for k, v := range score {
		out[k] = v
	}
	return out
}
