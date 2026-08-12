package service

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	cons "github.com/klouddb/klouddbshield/pkg/const"
)

var inactiveCountRE = regexp.MustCompile(`(\d+)\s+inactive`)

// collectCommonUsers lists login-capable DB roles from Users Report (inventory).
func (agg *fleetAccumulator) collectCommonUsers(host string, sections []usersReportSection) {
	for _, role := range loginRolesFromUsersList(sections) {
		agg.commonUserCount++
		agg.commonUserRows = append(agg.commonUserRows, []string{role, host, "View detail"})
	}
}

// collectInactiveUsers uses only inactive_users log-parser output (not password-expiry lists).
func (agg *fleetAccumulator) collectInactiveUsers(host string, report map[string]interface{}) {
	seen := map[string]bool{}
	for _, row := range inactiveUserRowsFromReport(host, report) {
		key := row[0] + "|" + row[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		agg.inactiveHosts[host] = true
		agg.inactiveRows = append(agg.inactiveRows, row)
	}
}

func inactiveUserRowsFromReport(host string, report map[string]interface{}) [][]string {
	var rows [][]string
	for _, e := range decodeLogParserEntries(report) {
		if logParserEntryCommand(e) != cons.LogParserCMD_InactiveUser {
			continue
		}
		names := inactiveUserNamesFromLogValue(e["Value"])
		if len(names) > 0 {
			for _, user := range names {
				if user == "" || isSystemRole(user) {
					continue
				}
				rows = append(rows, []string{user, host, "Inactive (log parser)", "View detail"})
			}
			continue
		}
		count, ok := logParserEntryCount(e)
		if !ok || count == 0 {
			continue
		}
		rows = append(rows, []string{"-", host, fmt.Sprintf("%d inactive (log parser)", count), "View detail"})
	}
	return rows
}

func inactiveUserNamesFromLogValue(val interface{}) []string {
	switch outer := val.(type) {
	case [][]string:
		if len(outer) < 3 {
			return nil
		}
		return trimInactiveUserNames(outer[2])
	case []interface{}:
		if len(outer) < 3 {
			return nil
		}
		switch third := outer[2].(type) {
		case []string:
			return trimInactiveUserNames(third)
		case []interface{}:
			names := make([]string, 0, len(third))
			for _, item := range third {
				name := strings.TrimSpace(fmt.Sprint(item))
				if name != "" && name != "<nil>" {
					names = append(names, name)
				}
			}
			return names
		}
	}
	return nil
}

func trimInactiveUserNames(users []string) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		name := strings.TrimSpace(user)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func logParserEntryCommand(e map[string]interface{}) string {
	return strings.TrimSpace(stringField(e, "command", "Command"))
}

func logParserEntryCount(e map[string]interface{}) (int, bool) {
	if n, ok := e["count"].(float64); ok {
		return int(n), true
	}
	if n, ok := e["count"].(int); ok {
		return n, true
	}
	result := stringField(e, "Result", "result")
	if m := inactiveCountRE.FindStringSubmatch(strings.ToLower(result)); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n, true
		}
	}
	return 0, false
}

func stringField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func logParserEntryHasIdentity(m map[string]interface{}) bool {
	return stringField(m, "title", "Title", "command", "Command") != ""
}

func normalizeLogParserEntry(m map[string]interface{}) map[string]interface{} {
	if _, ok := m["command"]; !ok {
		if c := stringField(m, "Command"); c != "" {
			m["command"] = c
		}
	}
	if _, ok := m["title"]; !ok {
		if t := stringField(m, "Title"); t != "" {
			m["title"] = t
		} else if cmd := stringField(m, "command", "Command"); cmd != "" {
			m["title"] = cmd
		}
	}
	if _, ok := m["result"]; !ok {
		if r, ok := m["Result"]; ok {
			m["result"] = r
		}
	}
	return m
}
