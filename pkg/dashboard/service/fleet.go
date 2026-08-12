package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

type fleetAccumulator struct {
	cisRows, sslRows, elevatedRows, piiRows, passwordRows,
	commonUserRows, configRows, inactiveRows, driftRows,
	hbaRows, defaultsRows, superuserRows [][]string

	cisHosts, sslHosts, elevatedHosts, piiHosts, passwordHosts,
	configHosts, inactiveHosts, driftHosts,
	hbaHosts, defaultsHosts, superuserHosts map[string]bool

	commonUserCount int
}

func newFleetAccumulator() *fleetAccumulator {
	return &fleetAccumulator{
		cisHosts:       map[string]bool{},
		sslHosts:       map[string]bool{},
		elevatedHosts:  map[string]bool{},
		piiHosts:       map[string]bool{},
		passwordHosts:  map[string]bool{},
		configHosts:    map[string]bool{},
		inactiveHosts:  map[string]bool{},
		driftHosts:     map[string]bool{},
		hbaHosts:       map[string]bool{},
		defaultsHosts:  map[string]bool{},
		superuserHosts: map[string]bool{},
	}
}

func fleetLevel(n int) string {
	if n == 0 {
		return "healthy"
	}
	if n > 5 {
		return "critical"
	}
	return "medium"
}

func fleetLevelUsers(n int) string {
	return fleetLevel(n)
}

// FleetCategories builds all fleet tiles from latest SQLite scan runs (prototype layout).
func (s *Service) FleetCategories(ctx context.Context) (*FleetCategoriesResponse, error) {
	runs, err := s.latestRunsByTarget(ctx)
	if err != nil {
		return nil, err
	}
	agg := newFleetAccumulator()

	for _, run := range runs {
		host := hostLabel(run)
		report := run.Report
		cis := decodeCISResults(report)
		failN := countFailedCIS(cis)
		_, runFailN, _ := runCISSummary(run)
		// Some persisted rows may have denormalized pass/fail columns even if report_json
		// decode is partial; keep CIS tile counts aligned with latest run totals.
		if failN == 0 && runFailN > 0 {
			failN = runFailN
		}

		if failN > 0 {
			agg.cisHosts[host] = true
			agg.cisRows = append(agg.cisRows, []string{
				host, compliancePctFromRun(run), fmt.Sprintf("%d", failN), "Open",
			})
		}

		hostSSL, hostConfig := false, false
		for _, r := range cis {
			if isConfigAuditControl(r) {
				st := cisResultStatus(r)
				if strings.EqualFold(st, "Fail") {
					hostConfig = true
				}
				agg.configRows = append(agg.configRows, []string{
					host,
					configAuditCheckLabel(r),
					st,
					configAuditAction(st),
				})
			}

			if !strings.EqualFold(r.Status, "Fail") {
				continue
			}
			title := strings.ToLower(r.Title + " " + r.Control + " " + r.FailReason)
			if strings.Contains(title, "ssl") || strings.Contains(title, "tls") {
				hostSSL = true
				agg.sslRows = append(agg.sslRows, []string{host, r.Title, "Critical", "Open"})
			}
			if cisMatchesAny(r, "guc", "log_", "shared_", "ssl", "wal_", "max_", "fsync") {
				agg.driftHosts[host] = true
				guc := r.Control
				if guc == "" {
					guc = trimForTable(r.Title, 40)
				}
				agg.driftRows = append(agg.driftRows, []string{host, guc, cisResultStatus(r), "Open"})
			}
			if strings.Contains(title, "password") || strings.Contains(title, "leak") {
				agg.passwordHosts[host] = true
				agg.passwordRows = append(agg.passwordRows, []string{host, "1", fleetTableDetailText(r.FailReason, r.Title), "Investigate"})
			}
		}
		if hostSSL {
			agg.sslHosts[host] = true
		}
		if hostConfig {
			agg.configHosts[host] = true
		}

		sections := decodeUsersReportSections(report)
		agg.collectElevatedPrivs(host, sections)
		agg.collectCommonUsers(host, sections)
		agg.collectHBAIssues(host, report)
		agg.collectUsageOfDefaults(host, run, sections)
		agg.collectSuperuserCounts(host, sections)

		if passwordManagerText(report) != "" || hasLogPasswordLeak(report) {
			if !agg.passwordHosts[host] {
				agg.passwordHosts[host] = true
				agg.passwordRows = append(agg.passwordRows, []string{host, "1", "Log/password audit", "Investigate"})
			}
		}

		piiRows, meta := decodePIIResults(resolvePIIReport(ctx, s.Repo, run))
		allPii := append(piiRows, meta...)
		if len(allPii) > 0 {
			agg.piiHosts[host] = true
			tables := map[string]bool{}
			for _, p := range allPii {
				if tbl := strings.TrimSpace(p.Table); tbl != "" {
					tables[tbl] = true
				}
			}
			db := strings.TrimSpace(run.TargetDB)
			if db == "" {
				db = "-"
			}
			agg.piiRows = append(agg.piiRows, []string{
				host, db, fmt.Sprintf("%d", len(tables)), "Scan",
			})
		}
	}

	inactiveRuns, err := s.latestRunsByTargetWithInactiveUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, run := range inactiveRuns {
		if run == nil || run.Report == nil {
			continue
		}
		agg.collectInactiveUsers(hostLabel(run), run.Report)
	}

	instanceDBs := buildInstanceDBIndex(runs)
	return &FleetCategoriesResponse{Categories: buildFleetCategoryList(agg, instanceDBs)}, nil
}

func buildInstanceDBIndex(runs []*reportstore.RunRow) map[string][]string {
	names := map[string]map[string]bool{}
	for _, run := range runs {
		if run == nil {
			continue
		}
		inst := instanceLabel(run)
		db := strings.TrimSpace(run.TargetDB)
		if db == "" {
			db = ParseHostKey(hostLabel(run)).Database
		}
		if db == "" {
			db = "postgres"
		}
		if names[inst] == nil {
			names[inst] = map[string]bool{}
		}
		names[inst][db] = true
	}
	out := map[string][]string{}
	for inst, set := range names {
		list := make([]string, 0, len(set))
		for db := range set {
			list = append(list, db)
		}
		sort.Strings(list)
		out[inst] = list
	}
	return out
}

func (agg *fleetAccumulator) collectElevatedPrivs(host string, sections []usersReportSection) {
	privMap := []struct {
		substr string
		label  string
	}{
		{"superuser", "SUPERUSER"},
		{"createdb", "CREATEDB"},
		{"createrole", "CREATEROLE"},
		{"bypassrls", "BYPASSRLS"},
	}
	for _, p := range privMap {
		sec := usersSectionByTitle(sections, p.substr)
		if sec == nil {
			continue
		}
		for _, row := range sec.Table.Rows {
			if len(row) == 0 {
				continue
			}
			role := row[0]
			if isSystemRole(role) {
				continue
			}
			agg.elevatedHosts[host] = true
			agg.elevatedRows = append(agg.elevatedRows, []string{host, role, p.label, "Open"})
		}
	}
}

func buildFleetCategoryList(agg *fleetAccumulator, instanceDBs map[string][]string) []FleetCategory {
	hostCount := func(m map[string]bool) int { return fleetUniqueInstances(m) }
	cisRows := groupFleetCISRows(agg.cisRows, instanceDBs)
	piiRows := groupFleetPIIRows(agg.piiRows, instanceDBs)
	passwordRows := groupFleetSingletonRows(agg.passwordRows, instanceDBs)
	defaultsRows := groupFleetSingletonRows(agg.defaultsRows, instanceDBs)
	superuserRows := groupFleetSingletonRows(agg.superuserRows, instanceDBs)
	sslCols := insertColAfterHost([]string{"Host", "Issue", "Severity", "Action"}, 0, "Database")
	elevatedCols := insertColAfterHost([]string{"Host", "Role", "Privilege", "Action"}, 0, "Database")
	configCols := insertColAfterHost([]string{"Host", "Check", "Result", "Action"}, 0, "Database")
	driftCols := insertColAfterHost([]string{"Host", "GUC", "Baseline vs live", "Action"}, 0, "Database")
	hbaCols := insertColAfterHost([]string{"Host", "Check", "Status", "Action"}, 0, "Database")
	return []FleetCategory{
		{
			ID: "cis-benchmarks", Title: "CIS Benchmarks", Level: fleetLevel(hostCount(agg.cisHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.cisHosts)), Menu: "Ciscollector Menu 2",
			Cols: []string{"Host", "Databases", "CIS score", "Failed controls", "Posture", "Action"}, Rows: cisRows,
		},
		{
			ID: "ssl-violations", Title: "SSL Violations", Level: fleetLevel(hostCount(agg.sslHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.sslHosts)), Menu: "Menu 15 · SSL Audit",
			Cols: sslCols, Rows: fleetRowsWithDatabaseColumn(agg.sslRows, 0),
		},
		{
			ID: "elevated-privs", Title: "Elevated Privs", Level: fleetLevel(hostCount(agg.elevatedHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.elevatedHosts)), Menu: "Users Report / Roles",
			Cols: elevatedCols, Rows: fleetRowsWithDatabaseColumn(agg.elevatedRows, 0),
		},
		{
			ID: "pii-violations", Title: "PII Violations", Level: fleetLevel(hostCount(agg.piiHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.piiHosts)), Menu: "Menu 4 · PII Scan",
			Cols: []string{"Host", "Databases", "High-conf tables", "Action"}, Rows: piiRows,
		},
		{
			ID: "password-leakage", Title: "Password Leakage", Level: fleetLevel(hostCount(agg.passwordHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.passwordHosts)), Menu: "Menu 10 · Password Leak",
			Cols: []string{"Host", "Databases", "Events (7d)", "Last seen", "Action"}, Rows: passwordRows,
		},
		{
			ID: "hba-issues", Title: "HBA Issues", Level: fleetLevel(hostCount(agg.hbaHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.hbaHosts)), Menu: "HBA Scanner · Menu 3",
			Cols: hbaCols, Rows: fleetRowsWithDatabaseColumn(agg.hbaRows, 0),
		},
		{
			ID: "usage-of-defaults", Title: "Usage of Defaults", Level: fleetLevel(hostCount(agg.defaultsHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.defaultsHosts)), Menu: "Critical Checks · Host Inventory",
			Cols: []string{"Host", "Databases", "Issue", "Detail", "Action"}, Rows: defaultsRows,
		},
		{
			ID: "superuser-counts", Title: "Superuser Counts", Level: fleetLevel(hostCount(agg.superuserHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.superuserHosts)), Menu: "Users Report · Top 25 Check #7",
			Cols: []string{"Host", "Databases", "Count", "Roles", "Action"}, Rows: superuserRows,
		},
		{
			ID: "common-users", Title: "Common Users", Level: fleetLevelUsers(agg.commonUserCount),
			Count: fmt.Sprintf("%d users", agg.commonUserCount), Menu: "Menu 9 → 4 · Role Audit",
			Cols: []string{"User name", "Host", "Database", "Action"}, UserTable: true,
			Rows: fleetUserTableRowsWithDatabase(agg.commonUserRows, 1),
		},
		{
			ID: "config-audit", Title: "Config Audit", Level: fleetLevel(hostCount(agg.configHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.configHosts)), Menu: "Menu 16 · Config Audit",
			Cols: configCols, Rows: fleetRowsWithDatabaseColumn(agg.configRows, 0),
		},
		{
			ID: "inactive-users", Title: "Inactive Users", Level: fleetLevel(hostCount(agg.inactiveHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.inactiveHosts)), Menu: "Menu 6 · pg_log Parser",
			Cols: []string{"User name", "Host", "Database", "Last login", "Action"}, UserTable: true,
			Rows: fleetUserTableRowsWithDatabase(agg.inactiveRows, 1),
		},
		{
			ID: "config-drift", Title: "Config Drift", Level: fleetLevel(hostCount(agg.driftHosts)),
			Count: fmt.Sprintf("%d hosts", hostCount(agg.driftHosts)), Menu: "Menu 17 · Compare",
			Cols: driftCols, Rows: fleetRowsWithDatabaseColumn(agg.driftRows, 0),
		},
	}
}
