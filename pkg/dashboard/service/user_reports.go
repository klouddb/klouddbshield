package service

import (
	"context"
	"sort"
	"strings"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

// InactiveUserReportRow is one inactive user across the fleet (grouped by instance).
type InactiveUserReportRow struct {
	User              string   `json:"user"`
	Host              string   `json:"host"`
	Instance          string   `json:"instance"`
	Databases         []string `json:"databases,omitempty"`
	DatabasesLabel    string   `json:"databases_label"`
	Status            string   `json:"status"`
	Begin             string   `json:"begin,omitempty"`
	End               string   `json:"end,omitempty"`
	TimeRangeLabel    string   `json:"time_range_label,omitempty"`
	InactiveSince     string   `json:"inactive_since,omitempty"`
	DaysInactive      int      `json:"days_inactive,omitempty"`
	InactivityBuckets []string `json:"inactivity_buckets,omitempty"`
	EligibleForReview bool     `json:"eligible_for_review,omitempty"`
	DataSource        string   `json:"data_source,omitempty"`
}

// InactiveUsersReportResponse is fleet-wide inactive users from log parser scans.
type InactiveUsersReportResponse struct {
	Rows         []InactiveUserReportRow `json:"rows"`
	HostCount    int                     `json:"hostCount"`
	UserCount    int                     `json:"userCount"`
	CountOver30  int                     `json:"countOver30,omitempty"`
	CountOver90  int                     `json:"countOver90,omitempty"`
	CountOver180 int                     `json:"countOver180,omitempty"`
	Message      string                  `json:"message,omitempty"`
}

// CommonUserReportRow is one login-capable DB role across the fleet (grouped by instance).
type CommonUserReportRow struct {
	User           string   `json:"user"`
	Host           string   `json:"host"`
	Instance       string   `json:"instance"`
	Databases      []string `json:"databases,omitempty"`
	DatabasesLabel string   `json:"databases_label"`
}

// CommonUsersReportResponse is fleet-wide login roles from Users Report scans.
type CommonUsersReportResponse struct {
	Rows      []CommonUserReportRow `json:"rows"`
	UserCount int                   `json:"userCount"`
	HostCount int                   `json:"hostCount"`
	Message   string                `json:"message,omitempty"`
}

type userInstanceAgg struct {
	user   string
	status string
	dbs    map[string]bool
	begin  string
	end    string
}

func mergeUserInstanceRow(agg map[string]*userInstanceAgg, user, host, status, begin, end string) {
	user = strings.TrimSpace(user)
	if user == "" || user == "-" {
		return
	}
	inst := fleetHostInstance(host)
	if inst == "" {
		inst = strings.TrimSpace(host)
	}
	db := fleetHostDatabase(host)
	key := user + "|" + inst
	row := agg[key]
	if row == nil {
		row = &userInstanceAgg{user: user, status: status, dbs: map[string]bool{}, begin: begin, end: end}
		agg[key] = row
	}
	if status != "" && row.status == "" {
		row.status = status
	}
	if row.begin == "" && begin != "" {
		row.begin = begin
	}
	if row.end == "" && end != "" {
		row.end = end
	}
	if db != "" {
		row.dbs[db] = true
	}
}

func userInstanceRowsFromAgg(agg map[string]*userInstanceAgg) []struct {
	user, inst, status, dbLabel, begin, end string
	dbs                                     []string
} {
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]struct {
		user, inst, status, dbLabel, begin, end string
		dbs                                     []string
	}, 0, len(keys))
	for _, k := range keys {
		row := agg[k]
		user, inst := row.user, ""
		if parts := strings.SplitN(k, "|", 2); len(parts) == 2 {
			if user == "" {
				user = parts[0]
			}
			inst = parts[1]
		}
		dbs := make([]string, 0, len(row.dbs))
		for db := range row.dbs {
			dbs = append(dbs, db)
		}
		sort.Strings(dbs)
		dbLabel := instanceDatabasesLabel(inst, map[string][]string{inst: dbs}, dbs)
		out = append(out, struct {
			user, inst, status, dbLabel, begin, end string
			dbs                                     []string
		}{user: user, inst: inst, status: row.status, dbLabel: dbLabel, dbs: dbs, begin: row.begin, end: row.end})
	}
	return out
}

func logFilterTimeRangeLabel(begin, end string) string {
	begin = strings.TrimSpace(begin)
	end = strings.TrimSpace(end)
	switch {
	case begin != "" && end != "":
		return begin + " → " + end
	case begin != "":
		return "from " + begin
	case end != "":
		return "until " + end
	default:
		return ""
	}
}

// InactiveUsersReport aggregates inactive_users log-parser output from latest scans per host.
func (s *Service) InactiveUsersReport(ctx context.Context) (*InactiveUsersReportResponse, error) {
	now := time.Now().UTC()
	resp := &InactiveUsersReportResponse{Rows: []InactiveUserReportRow{}}

	var aggStates []reportstore.LogParserInactiveUserState
	if s.Repo != nil {
		aggStates, _ = s.Repo.ListLogParserInactiveUsers(ctx)
	}
	aggTargets := aggregationTargetIDs(aggStates)
	if len(aggStates) > 0 {
		resp.Rows = append(resp.Rows, inactiveUserRowsFromAggregation(aggStates, now)...)
	}

	runs, err := s.latestRunsByTargetWithInactiveUsers(ctx)
	if err != nil {
		return nil, err
	}
	scanAgg := map[string]*userInstanceAgg{}
	for _, run := range runs {
		if run == nil || run.Report == nil {
			continue
		}
		if aggTargets[run.TargetID] {
			continue
		}
		host := hostLabel(run)
		meta := decodeLogParserScanMeta(run.Report)
		begin, end := "", ""
		if meta != nil {
			begin, end = meta.Begin, meta.End
		}
		for _, row := range inactiveUserRowsFromReport(host, run.Report) {
			if len(row) < 3 {
				continue
			}
			mergeUserInstanceRow(scanAgg, row[0], row[1], row[2], begin, end)
		}
	}
	for _, item := range userInstanceRowsFromAgg(scanAgg) {
		resp.Rows = append(resp.Rows, InactiveUserReportRow{
			User:           item.user,
			Host:           item.inst,
			Instance:       item.inst,
			Databases:      item.dbs,
			DatabasesLabel: item.dbLabel,
			Status:         item.status,
			Begin:          item.begin,
			End:            item.end,
			TimeRangeLabel: logFilterTimeRangeLabel(item.begin, item.end),
			DataSource:     "scan",
		})
	}

	sort.Slice(resp.Rows, func(i, j int) bool {
		a, b := resp.Rows[i], resp.Rows[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		return a.User < b.User
	})

	instances := map[string]bool{}
	users := map[string]bool{}
	for _, row := range resp.Rows {
		instances[row.Instance] = true
		users[row.User] = true
	}
	resp.HostCount = len(instances)
	resp.UserCount = len(users)
	resp.CountOver30, resp.CountOver90, resp.CountOver180 = countInactiveBuckets(resp.Rows)
	if len(resp.Rows) == 0 {
		resp.Message = "No inactive users found. Run collector with log parser inactive_users (menu 6) on each host."
	}
	return resp, nil
}

// UniqueIPReportRow is one unique client IP across the fleet (grouped by instance).
type UniqueIPReportRow struct {
	IP             string   `json:"ip"`
	Host           string   `json:"host"`
	Instance       string   `json:"instance"`
	Databases      []string `json:"databases,omitempty"`
	DatabasesLabel string   `json:"databases_label"`
	Begin          string   `json:"begin,omitempty"`
	End            string   `json:"end,omitempty"`
	TimeRangeLabel string   `json:"time_range_label,omitempty"`
	FirstSeen      string   `json:"first_seen,omitempty"`
	DataSource     string   `json:"data_source,omitempty"`
}

// UniqueIPReportResponse is fleet-wide unique client IPs from log parser scans.
type UniqueIPReportResponse struct {
	Rows      []UniqueIPReportRow `json:"rows"`
	HostCount int                 `json:"hostCount"`
	IPCount   int                 `json:"ipCount"`
	Message   string              `json:"message,omitempty"`
}

// UnusedLineReportRow is one unused HBA line across the fleet (grouped by instance).
type UnusedLineReportRow struct {
	LineNo            string   `json:"lineNo"`
	Line              string   `json:"line"`
	Host              string   `json:"host"`
	Instance          string   `json:"instance"`
	Databases         []string `json:"databases,omitempty"`
	DatabasesLabel    string   `json:"databases_label"`
	Begin             string   `json:"begin,omitempty"`
	End               string   `json:"end,omitempty"`
	TimeRangeLabel    string   `json:"time_range_label,omitempty"`
	UnusedSince       string   `json:"unused_since,omitempty"`
	DaysUnused        int      `json:"days_unused,omitempty"`
	InactivityBuckets []string `json:"inactivity_buckets,omitempty"`
	EligibleForReview bool     `json:"eligible_for_review,omitempty"`
	DataSource        string   `json:"data_source,omitempty"`
}

// UnusedLinesReportResponse is fleet-wide unused HBA lines from log parser scans.
type UnusedLinesReportResponse struct {
	Rows         []UnusedLineReportRow `json:"rows"`
	HostCount    int                   `json:"hostCount"`
	CountOver30  int                   `json:"countOver30,omitempty"`
	CountOver90  int                   `json:"countOver90,omitempty"`
	CountOver180 int                   `json:"countOver180,omitempty"`
	LineCount    int                   `json:"lineCount"`
	Message      string                `json:"message,omitempty"`
}

// PasswordLeakReportRow is one leaked password hit across the fleet (grouped by instance).
type PasswordLeakReportRow struct {
	Password       string   `json:"password"`
	Query          string   `json:"query"`
	Host           string   `json:"host"`
	Instance       string   `json:"instance"`
	Databases      []string `json:"databases,omitempty"`
	DatabasesLabel string   `json:"databases_label"`
	Begin          string   `json:"begin,omitempty"`
	End            string   `json:"end,omitempty"`
	TimeRangeLabel string   `json:"time_range_label,omitempty"`
}

// PasswordLeakReportResponse is fleet-wide password leak findings from log parser scans.
type PasswordLeakReportResponse struct {
	Rows      []PasswordLeakReportRow `json:"rows"`
	HostCount int                     `json:"hostCount"`
	LeakCount int                     `json:"leakCount"`
	Message   string                  `json:"message,omitempty"`
}

type keyedInstanceAgg struct {
	key    string
	inst   string
	status string
	dbs    map[string]bool
	begin  string
	end    string
}

func mergeKeyedInstanceRow(agg map[string]*keyedInstanceAgg, key, host, status, begin, end string) {
	key = strings.TrimSpace(key)
	if key == "" || key == "-" {
		return
	}
	inst := fleetHostInstance(host)
	if inst == "" {
		inst = strings.TrimSpace(host)
	}
	db := fleetHostDatabase(host)
	mapKey := key + "\x1e" + inst
	row := agg[mapKey]
	if row == nil {
		row = &keyedInstanceAgg{key: key, inst: inst, status: status, dbs: map[string]bool{}, begin: begin, end: end}
		agg[mapKey] = row
	}
	if status != "" && row.status == "" {
		row.status = status
	}
	if row.begin == "" && begin != "" {
		row.begin = begin
	}
	if row.end == "" && end != "" {
		row.end = end
	}
	if db != "" {
		row.dbs[db] = true
	}
}

func keyedInstanceRowsFromAgg(agg map[string]*keyedInstanceAgg) []struct {
	key, inst, status, dbLabel, begin, end string
	dbs                                    []string
} {
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]struct {
		key, inst, status, dbLabel, begin, end string
		dbs                                    []string
	}, 0, len(keys))
	for _, k := range keys {
		row := agg[k]
		dbs := make([]string, 0, len(row.dbs))
		for db := range row.dbs {
			dbs = append(dbs, db)
		}
		sort.Strings(dbs)
		dbLabel := instanceDatabasesLabel(row.inst, map[string][]string{row.inst: dbs}, dbs)
		out = append(out, struct {
			key, inst, status, dbLabel, begin, end string
			dbs                                    []string
		}{key: row.key, inst: row.inst, status: row.status, dbLabel: dbLabel, dbs: dbs, begin: row.begin, end: row.end})
	}
	return out
}

// UniqueIPReport aggregates unique_ip log-parser output from latest scans per host.
func (s *Service) UniqueIPReport(ctx context.Context) (*UniqueIPReportResponse, error) {
	resp := &UniqueIPReportResponse{Rows: []UniqueIPReportRow{}}

	var ipStates []reportstore.LogParserClientIPState
	aggTargets := map[string]bool{}
	if s.Repo != nil {
		ipStates, _ = s.Repo.ListLogParserClientIPs(ctx)
		for _, st := range ipStates {
			aggTargets[st.TargetID] = true
		}
	}
	if len(ipStates) > 0 {
		resp.Rows = append(resp.Rows, uniqueIPRowsFromAggregation(ipStates)...)
	}

	runs, err := s.latestRunsByTargetWithLogParser(ctx, cons.LogParserCMD_UniqueIPs)
	if err != nil {
		return nil, err
	}
	agg := map[string]*keyedInstanceAgg{}

	for _, run := range runs {
		if aggTargets[run.TargetID] {
			continue
		}
		if run == nil || run.Report == nil {
			continue
		}
		host := hostLabel(run)
		meta := decodeLogParserScanMeta(run.Report)
		begin, end := "", ""
		if meta != nil {
			begin, end = meta.Begin, meta.End
		}
		for _, ip := range uniqueIPsFromReport(run.Report) {
			mergeKeyedInstanceRow(agg, ip, host, "", begin, end)
		}
	}

	for _, item := range keyedInstanceRowsFromAgg(agg) {
		resp.Rows = append(resp.Rows, UniqueIPReportRow{
			IP:             item.key,
			Host:           item.inst,
			Instance:       item.inst,
			Databases:      item.dbs,
			DatabasesLabel: item.dbLabel,
			Begin:          item.begin,
			End:            item.end,
			TimeRangeLabel: logFilterTimeRangeLabel(item.begin, item.end),
			DataSource:     "scan",
		})
	}

	sort.Slice(resp.Rows, func(i, j int) bool {
		a, b := resp.Rows[i], resp.Rows[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		return a.IP < b.IP
	})

	instances := map[string]bool{}
	ips := map[string]bool{}
	for _, row := range resp.Rows {
		instances[row.Instance] = true
		ips[row.IP] = true
	}
	resp.HostCount = len(instances)
	resp.IPCount = len(ips)
	if len(resp.Rows) == 0 {
		resp.Message = "No unique client IPs found. Run collector with log parser unique_ip (menu 7) on each host."
	}
	return resp, nil
}

// UnusedLinesReport aggregates unused_lines log-parser output from latest scans per host.
func (s *Service) UnusedLinesReport(ctx context.Context) (*UnusedLinesReportResponse, error) {
	now := time.Now().UTC()
	resp := &UnusedLinesReportResponse{Rows: []UnusedLineReportRow{}}

	var hbaStates []reportstore.LogParserUnusedHBAState
	aggTargets := map[string]bool{}
	if s.Repo != nil {
		hbaStates, _ = s.Repo.ListLogParserUnusedHBALines(ctx)
		for _, st := range hbaStates {
			aggTargets[st.TargetID] = true
		}
	}
	if len(hbaStates) > 0 {
		resp.Rows = append(resp.Rows, unusedLineRowsFromAggregation(hbaStates, now)...)
	}

	runs, err := s.latestRunsByTargetWithLogParser(ctx, cons.LogParserCMD_HBAUnusedLines)
	if err != nil {
		return nil, err
	}
	agg := map[string]*keyedInstanceAgg{}

	for _, run := range runs {
		if aggTargets[run.TargetID] {
			continue
		}
		if run == nil || run.Report == nil {
			continue
		}
		host := hostLabel(run)
		meta := decodeLogParserScanMeta(run.Report)
		begin, end := "", ""
		if meta != nil {
			begin, end = meta.Begin, meta.End
		}
		for _, line := range unusedLinesFromReport(run.Report) {
			key := line.LineNo + "\x00" + line.Line
			mergeKeyedInstanceRow(agg, key, host, "", begin, end)
		}
	}

	for _, item := range keyedInstanceRowsFromAgg(agg) {
		lineNo, line := "", item.key
		if parts := strings.SplitN(item.key, "\x00", 2); len(parts) == 2 {
			lineNo, line = parts[0], parts[1]
		}
		resp.Rows = append(resp.Rows, UnusedLineReportRow{
			LineNo:         lineNo,
			Line:           line,
			Host:           item.inst,
			Instance:       item.inst,
			Databases:      item.dbs,
			DatabasesLabel: item.dbLabel,
			Begin:          item.begin,
			End:            item.end,
			TimeRangeLabel: logFilterTimeRangeLabel(item.begin, item.end),
			DataSource:     "scan",
		})
	}

	sort.Slice(resp.Rows, func(i, j int) bool {
		a, b := resp.Rows[i], resp.Rows[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		return a.LineNo+":"+a.Line < b.LineNo+":"+b.Line
	})

	instances := map[string]bool{}
	lineKeys := map[string]bool{}
	for _, row := range resp.Rows {
		instances[row.Instance] = true
		lineKeys[row.LineNo+"\x00"+row.Line] = true
	}
	resp.HostCount = len(instances)
	resp.LineCount = len(lineKeys)
	resp.CountOver30, resp.CountOver90, resp.CountOver180 = countUnusedLineBuckets(resp.Rows)
	if len(resp.Rows) == 0 {
		resp.Message = "No unused HBA lines found. Run collector with log parser unused_lines (menu 8) on each host."
	}
	return resp, nil
}

// PasswordLeakReport aggregates password_leak_scanner log-parser output from latest scans per host.
func (s *Service) PasswordLeakReport(ctx context.Context) (*PasswordLeakReportResponse, error) {
	runs, err := s.latestRunsByTargetWithLogParser(ctx, cons.LogParserCMD_PasswordLeakScanner)
	if err != nil {
		return nil, err
	}
	resp := &PasswordLeakReportResponse{Rows: []PasswordLeakReportRow{}}
	agg := map[string]*keyedInstanceAgg{}

	for _, run := range runs {
		if run == nil || run.Report == nil {
			continue
		}
		host := hostLabel(run)
		meta := decodeLogParserScanMeta(run.Report)
		begin, end := "", ""
		if meta != nil {
			begin, end = meta.Begin, meta.End
		}
		for _, hit := range passwordLeaksFromReport(run.Report) {
			key := hit.Password + "\x00" + hit.Query
			mergeKeyedInstanceRow(agg, key, host, "", begin, end)
		}
	}

	instances := map[string]bool{}
	leakKeys := map[string]bool{}
	for _, item := range keyedInstanceRowsFromAgg(agg) {
		instances[item.inst] = true
		leakKeys[item.key] = true
		password, query := "", item.key
		if parts := strings.SplitN(item.key, "\x00", 2); len(parts) == 2 {
			password, query = parts[0], parts[1]
		}
		resp.Rows = append(resp.Rows, PasswordLeakReportRow{
			Password:       password,
			Query:          query,
			Host:           item.inst,
			Instance:       item.inst,
			Databases:      item.dbs,
			DatabasesLabel: item.dbLabel,
			Begin:          item.begin,
			End:            item.end,
			TimeRangeLabel: logFilterTimeRangeLabel(item.begin, item.end),
		})
	}

	resp.HostCount = len(instances)
	resp.LeakCount = len(leakKeys)
	if len(resp.Rows) == 0 {
		resp.Message = "No leaked passwords found. Run collector with log parser password_leak_scanner (menu 10) on each host."
	}
	return resp, nil
}

// CommonUsersReport aggregates login-capable roles from Users Report across latest scans.
func (s *Service) CommonUsersReport(ctx context.Context) (*CommonUsersReportResponse, error) {
	runs, err := s.latestRunsByTarget(ctx)
	if err != nil {
		return nil, err
	}
	resp := &CommonUsersReportResponse{Rows: []CommonUserReportRow{}}
	agg := map[string]*userInstanceAgg{}

	for _, run := range runs {
		if run == nil || run.Report == nil {
			continue
		}
		host := hostLabel(run)
		sections := decodeUsersReportSections(run.Report)
		for _, role := range loginRolesFromUsersList(sections) {
			mergeUserInstanceRow(agg, role, host, "", "", "")
		}
	}

	instances := map[string]bool{}
	users := map[string]bool{}
	for _, item := range userInstanceRowsFromAgg(agg) {
		instances[item.inst] = true
		users[item.user] = true
		resp.Rows = append(resp.Rows, CommonUserReportRow{
			User:           item.user,
			Host:           item.inst,
			Instance:       item.inst,
			Databases:      item.dbs,
			DatabasesLabel: item.dbLabel,
		})
	}

	resp.HostCount = len(instances)
	resp.UserCount = len(users)
	if len(resp.Rows) == 0 {
		resp.Message = "No login-capable DB users in latest scans. Run collector with Users Report (menu 9) on each host."
	}
	return resp, nil
}
