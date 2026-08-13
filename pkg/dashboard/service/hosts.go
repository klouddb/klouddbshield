package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

// Hosts builds the hosts table grouped by PostgreSQL instance (host:port).
func (s *Service) Hosts(ctx context.Context) (*HostsResponse, error) {
	runs, err := s.latestRunsByTarget(ctx)
	if err != nil {
		return nil, err
	}
	grouped := map[string]*hostInstanceBuilder{}
	for _, run := range runs {
		if run == nil || run.Report == nil {
			continue
		}
		inst := instanceLabel(run)
		b := grouped[inst]
		if b == nil {
			b = &hostInstanceBuilder{instance: inst}
			grouped[inst] = b
		}
		b.add(run)
	}

	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	resp := &HostsResponse{Instances: make([]HostInstance, 0, len(keys))}
	for _, k := range keys {
		inst := grouped[k].build()
		resp.Instances = append(resp.Instances, inst)
		resp.Rows = append(resp.Rows, []string{
			inst.Instance,
			inst.IP,
			inst.DatabasesLabel,
			inst.PostureLabel,
			inst.FailLabel,
			inst.Agent,
			inst.LastAudit,
		})
	}
	return resp, nil
}

type hostInstanceBuilder struct {
	instance       string
	ip             string
	databases      []HostDatabaseBrief
	failing        int
	lastStartedAt  time.Time
	lastFinishedAt time.Time
}

func (b *hostInstanceBuilder) add(run *reportstore.RunRow) {
	brief := databaseBriefFromRun(run)
	if b.ip == "" && run.TargetHost != "" {
		b.ip = run.TargetHost
	}
	when := run.FinishedAt
	if when.IsZero() {
		when = run.StartedAt
	}
	best := b.lastFinishedAt
	if best.IsZero() {
		best = b.lastStartedAt
	}
	if when.After(best) {
		b.lastStartedAt = run.StartedAt
		b.lastFinishedAt = run.FinishedAt
	}
	b.databases = append(b.databases, brief)
	if brief.Posture == "Failing" {
		b.failing++
	}
}

func (b *hostInstanceBuilder) build() HostInstance {
	sort.Slice(b.databases, func(i, j int) bool {
		return b.databases[i].Name < b.databases[j].Name
	})
	names := make([]string, len(b.databases))
	for i, db := range b.databases {
		names[i] = db.Name
	}
	count := len(b.databases)
	posture := "Passing"
	if b.failing > 0 {
		posture = "Failing"
	}
	failLabel := instanceFailLabel(b.failing, count)
	postureLabel := instancePostureLabel(b.failing, count)
	dbLabel := fmt.Sprintf("%d (%s)", count, strings.Join(names, ", "))
	ip := b.ip
	if ip == "" {
		ip = "-"
	}
	return HostInstance{
		Instance:       b.instance,
		IP:             ip,
		DatabaseCount:  count,
		Databases:      b.databases,
		FailingCount:   b.failing,
		Posture:        posture,
		PostureLabel:   postureLabel,
		DatabasesLabel: dbLabel,
		FailLabel:      failLabel,
		Agent:          "Online",
		LastAudit:      relativeScanTimeWithDuration(b.lastStartedAt, b.lastFinishedAt),
	}
}

func instanceFailLabel(failing, total int) string {
	if total <= 0 {
		return ""
	}
	return fmt.Sprintf("%d/%d failing", failing, total)
}

func instancePostureLabel(failing, total int) string {
	if total <= 0 {
		return "-"
	}
	if failing <= 0 {
		return "Passing"
	}
	return fmt.Sprintf("%d/%d Failing", failing, total)
}

func databaseBriefFromRun(run *reportstore.RunRow) HostDatabaseBrief {
	cis := decodeCISResults(run.Report)
	passN, failN, score := runCISSummary(run)
	if len(cis) > 0 && passN+failN == 0 {
		passN, failN, score = summarizeCISResults(cis)
	}
	db := strings.TrimSpace(run.TargetDB)
	if db == "" {
		db = ParseHostKey(hostLabel(run)).Database
	}
	if db == "" {
		db = "postgres"
	}
	return HostDatabaseBrief{
		Name:      db,
		HostKey:   hostLabel(run),
		CisPct:    compliancePct(score, passN, failN),
		Posture:   hostStatus(score, failN),
		LastAudit: relativeScanTimeWithDuration(run.StartedAt, run.FinishedAt),
	}
}

// HostInstanceOverview returns database list for one PostgreSQL instance.
func (s *Service) HostInstanceOverview(ctx context.Context, instance string) (*HostInstanceResponse, error) {
	instance = strings.TrimSpace(instance)
	if instance == "" {
		return nil, nil
	}
	runs, err := s.latestRunsByTarget(ctx)
	if err != nil {
		return nil, err
	}
	resp := &HostInstanceResponse{Instance: instance}
	var latest time.Time
	for _, run := range runs {
		if run == nil || run.Report == nil {
			continue
		}
		if !strings.EqualFold(instanceLabel(run), instance) {
			continue
		}
		if resp.IP == "" && run.TargetHost != "" {
			resp.IP = run.TargetHost
		}
		brief := databaseBriefFromRun(run)
		resp.Databases = append(resp.Databases, brief)
		if run.StartedAt.After(latest) {
			latest = run.StartedAt
			resp.DefaultDB = brief.Name
		}
	}
	if len(resp.Databases) == 0 {
		return nil, nil
	}
	sort.Slice(resp.Databases, func(i, j int) bool {
		return resp.Databases[i].Name < resp.Databases[j].Name
	})
	if resp.DefaultDB == "" {
		resp.DefaultDB = resp.Databases[0].Name
	}
	if resp.IP == "" {
		resp.IP = "-"
	}
	return resp, nil
}
