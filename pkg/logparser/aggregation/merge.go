package aggregation

import (
	"strings"
	"time"
)

// MergeSinceSet updates tracked entities with a "since" timestamp.
// Unchanged keys keep their previous since; new keys get now; missing keys are removed.
func MergeSinceSet(previous map[string]time.Time, current []string, now time.Time) map[string]time.Time {
	cur := make(map[string]bool, len(current))
	for _, k := range current {
		k = trimKey(k)
		if k == "" {
			continue
		}
		cur[k] = true
	}
	out := make(map[string]time.Time, len(previous)+len(cur))
	for k, since := range previous {
		if cur[k] {
			out[k] = since
		}
	}
	for k := range cur {
		if _, ok := previous[k]; !ok {
			out[k] = now.UTC()
		}
	}
	return out
}

// MergeAccumulateSet adds new keys with first_seen=now; existing keys are unchanged.
func MergeAccumulateSet(previous map[string]time.Time, current []string, now time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(previous)+len(current))
	for k, since := range previous {
		out[k] = since
	}
	utc := now.UTC()
	for _, k := range current {
		k = trimKey(k)
		if k == "" {
			continue
		}
		if _, ok := out[k]; !ok {
			out[k] = utc
		}
	}
	return out
}

func trimKey(s string) string {
	return strings.TrimSpace(s)
}
