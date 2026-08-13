package backupcompliance

import (
	"testing"
	"time"
)

func TestInBackupWindow_Overnight(t *testing.T) {
	cases := []struct {
		clock string
		want  bool
	}{
		{"23:00", true},
		{"23:30", true},
		{"00:30", true},
		{"01:00", true},
		{"01:01", false},
		{"06:00", false},
		{"22:59", false},
	}
	for _, tc := range cases {
		tm, err := time.Parse("15:04", tc.clock)
		if err != nil {
			t.Fatal(err)
		}
		tm = time.Date(2026, 7, 10, tm.Hour(), tm.Minute(), 0, 0, time.UTC)
		got := InBackupWindow(tm, "23:00", "01:00", nil, "UTC")
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.clock, got, tc.want)
		}
	}
}

func TestInBackupWindow_Daytime(t *testing.T) {
	cases := []struct {
		clock string
		want  bool
	}{
		{"09:00", true},
		{"12:00", true},
		{"16:59", true},
		{"17:00", false},
		{"08:59", false},
	}
	for _, tc := range cases {
		tm, _ := time.Parse("15:04", tc.clock)
		tm = time.Date(2026, 7, 10, tm.Hour(), tm.Minute(), 0, 0, time.UTC)
		got := InBackupWindow(tm, "09:00", "17:00", nil, "UTC")
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.clock, got, tc.want)
		}
	}
}

func TestInBackupWindow_EmptyPolicyAuthorized(t *testing.T) {
	tm := time.Date(2026, 7, 10, 15, 0, 0, 0, time.UTC)
	if !InBackupWindow(tm, "", "", nil, "UTC") {
		t.Fatal("empty policy should authorize")
	}
	if ComplianceStatus(tm, "", "", nil, "UTC") != "authorized" {
		t.Fatal("expected authorized")
	}
}

func TestInBackupWindow_AllowedDays(t *testing.T) {
	days := []string{"saturday", "sunday"}
	sat := time.Date(2026, 7, 11, 3, 0, 0, 0, time.UTC)
	sun := time.Date(2026, 7, 12, 3, 0, 0, 0, time.UTC)
	mon := time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)

	if !InBackupWindow(sat, "02:00", "04:00", days, "UTC") {
		t.Fatal("Saturday 03:00 should be authorized")
	}
	if !InBackupWindow(sun, "02:00", "04:00", days, "UTC") {
		t.Fatal("Sunday 03:00 should be authorized")
	}
	if InBackupWindow(mon, "02:00", "04:00", days, "UTC") {
		t.Fatal("Monday 03:00 should be unauthorized")
	}
	if InBackupWindow(time.Date(2026, 7, 11, 15, 0, 0, 0, time.UTC), "02:00", "04:00", days, "UTC") {
		t.Fatal("Saturday 15:00 should be unauthorized")
	}
	if !InBackupWindow(sat, "02:00", "04:00", []string{"sat", "sun"}, "UTC") {
		t.Fatal("sat abbreviation should match Saturday")
	}
}

func TestInBackupWindow_TimezoneIST(t *testing.T) {
	tm := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	if !InBackupWindow(tm, "14:00", "15:00", nil, "Asia/Kolkata") {
		t.Fatal("09:00 UTC should be inside 14:00–15:00 IST")
	}
	if InBackupWindow(tm, "14:00", "15:00", nil, "UTC") {
		t.Fatal("09:00 UTC should be outside 14:00–15:00 UTC")
	}
}

func TestPolicyConfigured(t *testing.T) {
	if PolicyConfigured(Policy{}) {
		t.Fatal("empty should not be configured")
	}
	if !PolicyConfigured(Policy{AllowedStart: "02:00", AllowedEnd: "04:00"}) {
		t.Fatal("start+end should be configured")
	}
	if !PolicyConfigured(Policy{AllowedDays: []string{"saturday"}}) {
		t.Fatal("days-only should be configured")
	}
}

func TestBuildReport_Summary(t *testing.T) {
	rows := []RawBackup{
		{BackupType: "pg_dump", Status: "success", StartTime: time.Date(2026, 7, 10, 6, 0, 0, 0, time.UTC), EndTime: time.Date(2026, 7, 10, 6, 0, 30, 0, time.UTC)},
		{BackupType: "pg_dump", Status: "failed", StartTime: time.Date(2026, 7, 10, 7, 0, 0, 0, time.UTC)},
		{BackupType: "pg_dump", Status: "interrupted", StartTime: time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)},
		{BackupType: "pg_dump", Status: "auth_failed", StartTime: time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)},
		{BackupType: "pg_basebackup", Status: "running", StartTime: time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)},
		{BackupType: "pgbackrest", Status: "success", StartTime: time.Date(2026, 7, 10, 23, 30, 0, 0, time.UTC)},
	}
	r := BuildReport("localhost:5432", Policy{AllowedStart: "23:00", AllowedEnd: "01:00", Timezone: "UTC"}, rows, time.Now().UTC())
	if r.Summary.TotalBackups != 6 {
		t.Fatalf("total=%d", r.Summary.TotalBackups)
	}
	if r.Summary.Successful != 2 {
		t.Fatalf("success=%d want 2", r.Summary.Successful)
	}
	if r.Summary.Failed != 3 {
		t.Fatalf("failed=%d want 3", r.Summary.Failed)
	}
	if r.Summary.Running != 1 {
		t.Fatalf("running=%d want 1", r.Summary.Running)
	}
	if r.Summary.Unauthorized != 5 {
		t.Fatalf("unauthorized=%d want 5", r.Summary.Unauthorized)
	}
	if r.Backups[5].ComplianceStatus != "authorized" {
		t.Fatalf("last should be authorized, got %s", r.Backups[5].ComplianceStatus)
	}
}

func TestIsFailedStatus_ExtensionStatuses(t *testing.T) {
	for _, st := range []string{"failed", "interrupted", "auth_failed"} {
		if !IsFailedStatus(st) {
			t.Fatalf("%s should be failed", st)
		}
	}
	if IsFailedStatus("success") || IsFailedStatus("running") {
		t.Fatal("success/running must not be failed")
	}
}
