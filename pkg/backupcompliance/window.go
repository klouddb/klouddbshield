package backupcompliance

import (
	"fmt"
	"strings"
	"time"
)

// ParseClock parses "HH:MM" or "HH:MM:SS" into minutes since midnight.
func ParseClock(s string) (minutes int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	var h, m, sec int
	n, err := fmt.Sscanf(s, "%d:%d:%d", &h, &m, &sec)
	if err != nil || n < 2 {
		n, err = fmt.Sscanf(s, "%d:%d", &h, &m)
		if err != nil || n != 2 {
			return 0, false
		}
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// ResolveLocation returns an IANA timezone, or Local when empty/invalid.
func ResolveLocation(timezone string) *time.Location {
	timezone = strings.TrimSpace(timezone)
	if timezone == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Local
	}
	return loc
}

// WeekdayAllowed reports whether t's weekday is in allowedDays.
// Empty/nil allowedDays → all days allowed.
func WeekdayAllowed(t time.Time, allowedDays []string) bool {
	if len(allowedDays) == 0 {
		return true
	}
	wd := t.Weekday()
	for _, d := range allowedDays {
		if matchWeekday(d, wd) {
			return true
		}
	}
	return false
}

func matchWeekday(name string, wd time.Weekday) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sunday", "sun":
		return wd == time.Sunday
	case "monday", "mon":
		return wd == time.Monday
	case "tuesday", "tue", "tues":
		return wd == time.Tuesday
	case "wednesday", "wed":
		return wd == time.Wednesday
	case "thursday", "thu", "thur", "thurs":
		return wd == time.Thursday
	case "friday", "fri":
		return wd == time.Friday
	case "saturday", "sat":
		return wd == time.Saturday
	default:
		return false
	}
}

// InBackupWindow reports whether t falls inside the authorized policy.
// Clock and weekday are evaluated in timezone (empty = Local).
func InBackupWindow(t time.Time, allowedStart, allowedEnd string, allowedDays []string, timezone string) bool {
	t = t.In(ResolveLocation(timezone))
	if !WeekdayAllowed(t, allowedDays) {
		return false
	}
	startMin, startOK := ParseClock(allowedStart)
	endMin, endOK := ParseClock(allowedEnd)
	if !startOK || !endOK {
		return true
	}
	tm := t.Hour()*60 + t.Minute()
	if startMin == endMin {
		return tm == startMin
	}
	if startMin < endMin {
		return tm >= startMin && tm < endMin
	}
	return tm >= startMin || tm <= endMin
}

// PolicyConfigured reports whether a policy has a usable time window and/or days.
func PolicyConfigured(p Policy) bool {
	_, startOK := ParseClock(p.AllowedStart)
	_, endOK := ParseClock(p.AllowedEnd)
	if startOK && endOK {
		return true
	}
	for _, d := range p.AllowedDays {
		if strings.TrimSpace(d) != "" {
			return true
		}
	}
	return false
}

// ComplianceStatus returns "authorized" or "unauthorized".
func ComplianceStatus(t time.Time, allowedStart, allowedEnd string, allowedDays []string, timezone string) string {
	if InBackupWindow(t, allowedStart, allowedEnd, allowedDays, timezone) {
		return "authorized"
	}
	return "unauthorized"
}

// PolicyComplianceStatus evaluates t against a full Policy.
func PolicyComplianceStatus(t time.Time, p Policy) string {
	return ComplianceStatus(t, p.AllowedStart, p.AllowedEnd, p.AllowedDays, p.Timezone)
}
