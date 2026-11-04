package aggregation

import (
	"fmt"
	"strings"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
)

// UnusedHBALine is one unused pg_hba line from a scan.
type UnusedHBALine struct {
	LineNo string
	Line   string
}

// ScanMeta holds log filter window from a scan report.
type ScanMeta struct {
	Begin string
	End   string
}

// MinValidationDays is how many days of inactivity are required before drop eligibility.
const MinValidationDays = 30

const (
	BucketOver30  = "gt30"
	BucketOver90  = "gt90"
	BucketOver180 = "gt180"
)

// InactivityBuckets returns tier labels for how long an entity has been inactive.
func InactivityBuckets(since time.Time, now time.Time) []string {
	if since.IsZero() {
		return nil
	}
	days := int(now.Sub(since).Hours() / 24)
	if days < 0 {
		days = 0
	}
	var tiers []string
	if days > 30 {
		tiers = append(tiers, BucketOver30)
	}
	if days > 90 {
		tiers = append(tiers, BucketOver90)
	}
	if days > 180 {
		tiers = append(tiers, BucketOver180)
	}
	return tiers
}

// EligibleForDropReview is true when inactive at least MinValidationDays.
func EligibleForDropReview(since time.Time, now time.Time) bool {
	if since.IsZero() {
		return false
	}
	days := int(now.Sub(since).Hours() / 24)
	return days >= MinValidationDays
}

func isSystemRole(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "pg_")
}

// InactiveUsersFromReport returns DB users inactive in this scan (not seen in logs).
func InactiveUsersFromReport(report map[string]interface{}) []string {
	var names []string
	for _, e := range decodeLogParserEntries(report) {
		if entryCommand(e) != cons.LogParserCMD_InactiveUser {
			continue
		}
		for _, u := range inactiveUserNamesFromValue(e["Value"]) {
			if u == "" || isSystemRole(u) {
				continue
			}
			names = append(names, u)
		}
	}
	return uniqueStrings(names)
}

// ClientIPsFromReport returns client IPs seen in this scan.
func ClientIPsFromReport(report map[string]interface{}) []string {
	var ips []string
	for _, e := range decodeLogParserEntries(report) {
		if entryCommand(e) != cons.LogParserCMD_UniqueIPs {
			continue
		}
		ips = append(ips, stringList(e["Value"])...)
	}
	return uniqueStrings(ips)
}

// UnusedHBALinesFromReport returns unused HBA lines from this scan.
func UnusedHBALinesFromReport(report map[string]interface{}) []UnusedHBALine {
	var lines []UnusedHBALine
	for _, e := range decodeLogParserEntries(report) {
		if entryCommand(e) != cons.LogParserCMD_HBAUnusedLines {
			continue
		}
		raw, ok := e["Value"].([]interface{})
		if !ok {
			continue
		}
		for _, item := range raw {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			lineNo := stringField(m, "LineNo", "lineNo", "line_no", "LineNumber")
			line := stringField(m, "Line", "line")
			if lineNo == "" && line == "" {
				continue
			}
			lines = append(lines, UnusedHBALine{LineNo: lineNo, Line: line})
		}
	}
	return lines
}

// ScanMetaFromReport reads begin/end from Log Parser Scan Meta.
func ScanMetaFromReport(report map[string]interface{}) ScanMeta {
	if report == nil {
		return ScanMeta{}
	}
	raw, ok := report["Log Parser Scan Meta"]
	if !ok {
		return ScanMeta{}
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return ScanMeta{}
	}
	return ScanMeta{
		Begin: strings.TrimSpace(fmt.Sprint(m["begin"])),
		End:   strings.TrimSpace(fmt.Sprint(m["end"])),
	}
}

// ShouldApplyScanSnapshot is false for empty findings on a windowed cron scan
// (short log filter windows must not wipe long-lived aggregation state).
func ShouldApplyScanSnapshot(report map[string]interface{}, command string, findingsNonEmpty bool) bool {
	if !reportHasCommand(report, command) {
		return false
	}
	if findingsNonEmpty {
		return true
	}
	meta := ScanMetaFromReport(report)
	if meta.Begin != "" || meta.End != "" {
		return false
	}
	return true
}

func reportHasCommand(report map[string]interface{}, command string) bool {
	for _, e := range decodeLogParserEntries(report) {
		if entryCommand(e) == command {
			return true
		}
	}
	return false
}

func unusedLineEntityKey(line UnusedHBALine) string {
	return line.LineNo + "\x00" + line.Line
}

func decodeLogParserEntries(report map[string]interface{}) []map[string]interface{} {
	raw, ok := report["Log Parser Summary"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		var out []map[string]interface{}
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func entryCommand(e map[string]interface{}) string {
	if e == nil {
		return ""
	}
	if c, ok := e["Command"].(string); ok {
		return strings.TrimSpace(c)
	}
	if c, ok := e["command"].(string); ok {
		return strings.TrimSpace(c)
	}
	return ""
}

func inactiveUserNamesFromValue(val interface{}) []string {
	switch outer := val.(type) {
	case [][]string:
		if len(outer) < 3 {
			return nil
		}
		return trimNames(outer[2])
	case []interface{}:
		if len(outer) < 3 {
			return nil
		}
		switch third := outer[2].(type) {
		case []string:
			return trimNames(third)
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

func trimNames(users []string) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		name := strings.TrimSpace(user)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func stringList(val interface{}) []string {
	switch v := val.(type) {
	case []string:
		return trimNames(v)
	case []interface{}:
		var out []string
		for _, item := range v {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" && s != "<nil>" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func stringField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// EntityKeysForUnusedLines builds stable keys for unused HBA lines.
func EntityKeysForUnusedLines(lines []UnusedHBALine) []string {
	keys := make([]string, 0, len(lines))
	for _, l := range lines {
		k := unusedLineEntityKey(l)
		if k != "\x00" {
			keys = append(keys, k)
		}
	}
	return keys
}
