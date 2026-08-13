package main

import (
	"time"

	dashboardsvc "github.com/klouddb/klouddbshield/pkg/dashboard/service"
	mainserversvc "github.com/klouddb/klouddbshield/pkg/mainserver/service"
	"github.com/klouddb/klouddbshield/pkg/repository"
)

type App struct {
	DBFilePath        string
	Repo              repository.Repository
	Svc               *mainserversvc.Service
	DashboardSvc      *dashboardsvc.Service
	KshieldConfigPath string
	ServerConfig      ServerConfig
	WSHub             *Hub
}

type OverviewResponse struct {
	Summary       Summary   `json:"summary"`
	CentralServer Server    `json:"central_server"`
	Servers       []Server  `json:"servers"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Summary struct {
	Servers  int `json:"servers"`
	Healthy  int `json:"healthy"`
	Warning  int `json:"warning"`
	Critical int `json:"critical"`
}

type Server struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	IP            string        `json:"ip"`
	Status        string        `json:"status"`
	ServerSummary ServerSummary `json:"server_summary"`
}

type ServerSummary struct {
	TotalCases  int `json:"total_cases"`
	PassedCases int `json:"passed_cases"`
}

type NodeInfo struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	IP          string      `json:"ip"`
	AgentConfig AgentConfig `json:"agent_config"`
}

type NodeData struct {
	GucSettings *GucSettingsPayload `json:"guc_settings,omitempty"`
}

type GucSettingsPayload struct {
	Settings map[string]string `json:"settings"`
	ScanMeta ScanMetadata      `json:"scan_meta"`
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
