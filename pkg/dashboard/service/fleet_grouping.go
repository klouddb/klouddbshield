package service

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func fleetHostInstance(host string) string {
	p := ParseHostKey(host)
	if p.Instance != "" {
		return p.Instance
	}
	return strings.TrimSpace(host)
}

func fleetHostDatabase(host string) string {
	return ParseHostKey(host).Database
}

func fleetUniqueInstances(hosts map[string]bool) int {
	if len(hosts) == 0 {
		return 0
	}
	seen := map[string]bool{}
	for host := range hosts {
		inst := fleetHostInstance(host)
		if inst == "" {
			continue
		}
		seen[inst] = true
	}
	return len(seen)
}

func instanceDatabasesLabel(instance string, instanceDBs map[string][]string, fallback []string) string {
	names := instanceDBNames(instance, instanceDBs, nil)
	if len(names) == 0 {
		names = append([]string(nil), fallback...)
		sort.Strings(names)
	}
	if len(names) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d (%s)", len(names), strings.Join(names, ", "))
}

func instanceDBNames(instance string, instanceDBs map[string][]string, rows [][]string) []string {
	if instanceDBs != nil {
		if names := instanceDBs[instance]; len(names) > 0 {
			return names
		}
		for inst, names := range instanceDBs {
			if strings.EqualFold(inst, instance) && len(names) > 0 {
				return names
			}
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0)
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		db := fleetHostDatabase(row[0])
		if db == "" || seen[db] {
			continue
		}
		seen[db] = true
		out = append(out, db)
	}
	sort.Strings(out)
	return out
}

func parsePctString(pct string) int {
	pct = strings.TrimSpace(strings.TrimSuffix(pct, "%"))
	n, _ := strconv.Atoi(pct)
	return n
}

func groupFleetCISRows(rows [][]string, instanceDBs map[string][]string) [][]string {
	type dbCIS struct {
		name   string
		score  int
		failed int
	}
	grouped := map[string][]dbCIS{}
	order := make([]string, 0)
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		host := row[0]
		inst := fleetHostInstance(host)
		db := fleetHostDatabase(host)
		if db == "" {
			db = host
		}
		if _, ok := grouped[inst]; !ok {
			order = append(order, inst)
		}
		failed, _ := strconv.Atoi(strings.TrimSpace(row[2]))
		grouped[inst] = append(grouped[inst], dbCIS{
			name:   db,
			score:  parsePctString(row[1]),
			failed: failed,
		})
	}
	sort.Strings(order)
	out := make([][]string, 0, len(order))
	for _, inst := range order {
		dbs := grouped[inst]
		sort.Slice(dbs, func(i, j int) bool { return dbs[i].name < dbs[j].name })
		names := make([]string, len(dbs))
		worstScore := -1
		maxFailed := 0
		for i, db := range dbs {
			names[i] = db.name
			if worstScore < 0 || db.score < worstScore {
				worstScore = db.score
			}
			if db.failed > maxFailed {
				maxFailed = db.failed
			}
		}
		if worstScore < 0 {
			worstScore = 0
		}
		total := len(instanceDBs[inst])
		if total <= 0 {
			total = len(dbs)
		}
		failing := len(dbs)
		out = append(out, []string{
			inst,
			instanceDatabasesLabel(inst, instanceDBs, names),
			fmt.Sprintf("%d%%", worstScore),
			fmt.Sprintf("%d", maxFailed),
			instancePostureLabel(failing, total),
			"Open",
		})
	}
	return out
}

func groupFleetPIIRows(rows [][]string, instanceDBs map[string][]string) [][]string {
	type instPII struct {
		dbs    map[string]int
		tables int
	}
	grouped := map[string]*instPII{}
	order := make([]string, 0)
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		inst := fleetHostInstance(row[0])
		db := fleetHostDatabase(row[0])
		if db == "" {
			db = strings.TrimSpace(row[1])
		}
		tables, _ := strconv.Atoi(strings.TrimSpace(row[2]))
		g := grouped[inst]
		if g == nil {
			g = &instPII{dbs: map[string]int{}}
			grouped[inst] = g
			order = append(order, inst)
		}
		g.dbs[db] += tables
		g.tables += tables
	}
	sort.Strings(order)
	out := make([][]string, 0, len(order))
	for _, inst := range order {
		g := grouped[inst]
		names := make([]string, 0, len(g.dbs))
		for db := range g.dbs {
			names = append(names, db)
		}
		out = append(out, []string{
			inst,
			instanceDatabasesLabel(inst, instanceDBs, names),
			fmt.Sprintf("%d", g.tables),
			"Scan",
		})
	}
	return out
}

func groupFleetSingletonRows(rows [][]string, instanceDBs map[string][]string) [][]string {
	grouped := map[string][][]string{}
	order := make([]string, 0)
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		inst := fleetHostInstance(row[0])
		if _, ok := grouped[inst]; !ok {
			order = append(order, inst)
		}
		grouped[inst] = append(grouped[inst], row)
	}
	sort.Strings(order)
	out := make([][]string, 0, len(order))
	for _, inst := range order {
		rowsForInst := grouped[inst]
		base := append([]string(nil), rowsForInst[0]...)
		base[0] = inst
		names := instanceDBNames(inst, instanceDBs, rowsForInst)
		label := instanceDatabasesLabel(inst, instanceDBs, names)
		base = append([]string{inst, label}, base[1:]...)
		out = append(out, base)
	}
	return out
}

func fleetRowsWithDatabaseColumn(rows [][]string, hostCol int) [][]string {
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		if len(row) <= hostCol {
			continue
		}
		host := row[hostCol]
		inst := fleetHostInstance(host)
		db := fleetHostDatabase(host)
		if db == "" {
			db = "-"
		}
		newRow := make([]string, 0, len(row)+1)
		newRow = append(newRow, inst, db)
		for i, cell := range row {
			if i == hostCol {
				continue
			}
			newRow = append(newRow, cell)
		}
		out = append(out, newRow)
	}
	return out
}

func fleetUserTableRowsWithDatabase(rows [][]string, hostCol int) [][]string {
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		if len(row) <= hostCol {
			continue
		}
		host := row[hostCol]
		inst := fleetHostInstance(host)
		db := fleetHostDatabase(host)
		if db == "" {
			db = "postgres"
		}
		newRow := make([]string, 0, len(row)+1)
		for i, cell := range row {
			if i == hostCol {
				newRow = append(newRow, inst, db)
			} else {
				newRow = append(newRow, cell)
			}
		}
		out = append(out, newRow)
	}
	return out
}

func insertColAfterHost(cols []string, hostIdx int, colName string) []string {
	if hostIdx < 0 || hostIdx >= len(cols) {
		return cols
	}
	out := append([]string(nil), cols[:hostIdx+1]...)
	out = append(out, colName)
	out = append(out, cols[hostIdx+1:]...)
	return out
}
