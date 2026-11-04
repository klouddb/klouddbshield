package service

import (
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/logparser/aggregation"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
)

func hostKeyFromTargetID(targetID string) string {
	parts := strings.Split(targetID, ":")
	if len(parts) >= 4 && strings.EqualFold(parts[0], "postgres") {
		return parts[1] + ":" + parts[2] + "/" + parts[3]
	}
	if len(parts) >= 3 && strings.EqualFold(parts[0], "postgres") {
		return parts[1] + ":" + parts[2]
	}
	return strings.TrimSpace(targetID)
}

func inactiveUserRowsFromAggregation(states []reportstore.LogParserInactiveUserState, now time.Time) []InactiveUserReportRow {
	agg := map[string]*userInstanceAgg{}
	for _, st := range states {
		host := hostKeyFromTargetID(st.TargetID)
		if host == "" || st.TargetID == "" {
			host = strings.TrimSpace(st.TargetHost)
		}
		since := st.InactiveSince.UTC().Format(time.RFC3339)
		status := "Inactive (aggregated)"
		if aggregation.EligibleForDropReview(st.InactiveSince, now) {
			status = "Inactive ≥30d (eligible for review)"
		}
		mergeUserInstanceRow(agg, st.User, host, status, since, "")
	}
	rows := make([]InactiveUserReportRow, 0, len(agg))
	for _, item := range userInstanceRowsFromAgg(agg) {
		sinceT, _ := time.Parse(time.RFC3339, item.begin)
		days := 0
		var buckets []string
		if !sinceT.IsZero() {
			days = int(now.Sub(sinceT).Hours() / 24)
			if days < 0 {
				days = 0
			}
			buckets = aggregation.InactivityBuckets(sinceT, now)
		}
		rows = append(rows, InactiveUserReportRow{
			User:              item.user,
			Host:              item.inst,
			Instance:          item.inst,
			Databases:         item.dbs,
			DatabasesLabel:    item.dbLabel,
			Status:            item.status,
			Begin:             item.begin,
			End:               item.end,
			TimeRangeLabel:    "inactive since " + item.begin,
			InactiveSince:     item.begin,
			DaysInactive:      days,
			InactivityBuckets: buckets,
			EligibleForReview: aggregation.EligibleForDropReview(sinceT, now),
			DataSource:        "aggregation",
		})
	}
	return rows
}

func uniqueIPRowsFromAggregation(states []reportstore.LogParserClientIPState) []UniqueIPReportRow {
	agg := map[string]*keyedInstanceAgg{}
	for _, st := range states {
		host := hostKeyFromTargetID(st.TargetID)
		if host == "" {
			host = strings.TrimSpace(st.TargetHost)
		}
		first := st.FirstSeen.UTC().Format(time.RFC3339)
		mergeKeyedInstanceRow(agg, st.IP, host, "", first, "")
	}
	rows := make([]UniqueIPReportRow, 0, len(agg))
	for _, item := range keyedInstanceRowsFromAgg(agg) {
		rows = append(rows, UniqueIPReportRow{
			IP:             item.key,
			Host:           item.inst,
			Instance:       item.inst,
			Databases:      item.dbs,
			DatabasesLabel: item.dbLabel,
			Begin:          item.begin,
			End:            item.end,
			TimeRangeLabel: "first seen " + item.begin,
			FirstSeen:      item.begin,
			DataSource:     "aggregation",
		})
	}
	return rows
}

func unusedLineRowsFromAggregation(states []reportstore.LogParserUnusedHBAState, now time.Time) []UnusedLineReportRow {
	agg := map[string]*keyedInstanceAgg{}
	for _, st := range states {
		host := hostKeyFromTargetID(st.TargetID)
		if host == "" {
			host = strings.TrimSpace(st.TargetHost)
		}
		since := st.UnusedSince.UTC().Format(time.RFC3339)
		key := st.EntityKey
		if key == "" {
			key = st.LineNo + "\x00" + st.LineText
		}
		mergeKeyedInstanceRow(agg, key, host, "", since, "")
	}
	rows := make([]UnusedLineReportRow, 0, len(agg))
	for _, item := range keyedInstanceRowsFromAgg(agg) {
		lineNo, line := "", item.key
		if parts := strings.SplitN(item.key, "\x00", 2); len(parts) == 2 {
			lineNo, line = parts[0], parts[1]
		}
		sinceT, _ := time.Parse(time.RFC3339, item.begin)
		days := 0
		var buckets []string
		if !sinceT.IsZero() {
			days = int(now.Sub(sinceT).Hours() / 24)
			if days < 0 {
				days = 0
			}
			buckets = aggregation.InactivityBuckets(sinceT, now)
		}
		rows = append(rows, UnusedLineReportRow{
			LineNo:            lineNo,
			Line:              line,
			Host:              item.inst,
			Instance:          item.inst,
			Databases:         item.dbs,
			DatabasesLabel:    item.dbLabel,
			Begin:             item.begin,
			End:               item.end,
			TimeRangeLabel:    "unused since " + item.begin,
			UnusedSince:       item.begin,
			DaysUnused:        days,
			InactivityBuckets: buckets,
			EligibleForReview: aggregation.EligibleForDropReview(sinceT, now),
			DataSource:        "aggregation",
		})
	}
	return rows
}

func aggregationTargetIDs(states []reportstore.LogParserInactiveUserState) map[string]bool {
	out := map[string]bool{}
	for _, st := range states {
		if st.TargetID != "" {
			out[st.TargetID] = true
		}
	}
	return out
}

func countInactiveBuckets(rows []InactiveUserReportRow) (over30, over90, over180 int) {
	for _, r := range rows {
		over30, over90, over180 = addBucketCounts(r.InactivityBuckets, over30, over90, over180)
	}
	return over30, over90, over180
}

func countUnusedLineBuckets(rows []UnusedLineReportRow) (over30, over90, over180 int) {
	for _, r := range rows {
		over30, over90, over180 = addBucketCounts(r.InactivityBuckets, over30, over90, over180)
	}
	return over30, over90, over180
}

func addBucketCounts(buckets []string, over30, over90, over180 int) (int, int, int) {
	for _, b := range buckets {
		switch b {
		case aggregation.BucketOver30:
			over30++
		case aggregation.BucketOver90:
			over90++
		case aggregation.BucketOver180:
			over180++
		}
	}
	return over30, over90, over180
}
