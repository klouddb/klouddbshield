package aggregation

import (
	"testing"
	"time"
)

func TestMergeSinceSet(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	prev := map[string]time.Time{
		"A": time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC),
		"B": time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		"C": time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
	}

	// unchanged
	out := MergeSinceSet(prev, []string{"A", "B", "C"}, now)
	if len(out) != 3 || !out["A"].Equal(prev["A"]) {
		t.Fatalf("unchanged: %#v", out)
	}

	// new D
	out = MergeSinceSet(prev, []string{"A", "B", "C", "D"}, now)
	if !out["D"].Equal(now) {
		t.Fatalf("D since=%v want %v", out["D"], now)
	}

	// remove B
	out = MergeSinceSet(prev, []string{"A", "C", "D"}, now)
	if _, ok := out["B"]; ok {
		t.Fatal("B should be removed")
	}

	// re-add B
	out = MergeSinceSet(map[string]time.Time{"A": prev["A"]}, []string{"A", "B"}, now)
	if !out["B"].Equal(now) {
		t.Fatalf("re-added B since=%v want %v", out["B"], now)
	}
}

func TestMergeAccumulateSet(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	prev := map[string]time.Time{
		"1.2.3.4": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	out := MergeAccumulateSet(prev, []string{"1.2.3.4", "5.6.7.8"}, now)
	if !out["1.2.3.4"].Equal(prev["1.2.3.4"]) {
		t.Fatal("existing IP first_seen changed")
	}
	if !out["5.6.7.8"].Equal(now) {
		t.Fatal("new IP first_seen")
	}
}
