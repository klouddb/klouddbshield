package backuphistory

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var weekDayMap = map[string]int{
	"Monday":    1,
	"Tuesday":   2,
	"Wednesday": 3,
	"Thursday":  4,
	"Friday":    5,
	"Saturday":  6,
	"Sunday":    7,
	"Mon":       1,
	"Tue":       2,
	"Wed":       3,
	"Thu":       4,
	"Fri":       5,
	"Sat":       6,
	"Sun":       7,
}

var monthMap = map[string]int{
	"January":   1,
	"February":  2,
	"March":     3,
	"April":     4,
	"May":       5,
	"June":      6,
	"July":      7,
	"August":    8,
	"September": 9,
	"October":   10,
	"November":  11,
	"December":  12,
	"Jan":       1,
	"Feb":       2,
	"Mar":       3,
	"Apr":       4,
	"Jun":       6,
	"Jul":       7,
	"Aug":       8,
	"Sep":       9,
	"Oct":       10,
	"Nov":       11,
	"Dec":       12,
}

var mapForPrefix = map[string]placeholderUpdate{
	"%Y": {
		Regex: `\d{4}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Year, err = strconv.Atoi(s)
			return err
		},
	},
	"%y": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Year, err = strconv.Atoi(s)
			return err
		},
	},
	"%m": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Month, err = strconv.Atoi(s)
			return err
		},
	},
	"%d": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Day, err = strconv.Atoi(s)
			return err
		},
	},
	"%H": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Hour, err = strconv.Atoi(s)
			if err != nil {
				return err
			}
			if t.Hour >= 12 {
				t.Add12InHour = true
				t.Hour -= 12
			}
			return nil
		},
	},
	"%M": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Minute, err = strconv.Atoi(s)
			return err
		},
	},
	"%S": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Second, err = strconv.Atoi(s)
			return err
		},
	},
	"%A": {
		Regex: `\w+`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.Weekday = weekDayMap[s]
			return nil
		},
	},
	"%a": {
		Regex: `\w+`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.Weekday = weekDayMap[s]
			return nil
		},
	},
	"%w": {
		Regex: `\d{1,2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.Weekday = weekDayMap[s]
			return nil
		},
	},
	"%W": {
		Regex: `\d{1,2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.WeekNum, _ = strconv.Atoi(s)
			return nil
		},
	},
	"%B": {
		Regex: `\w+`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.Month = monthMap[s]
			return nil
		},
	},
	"%b": {
		Regex: `\w+`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.Month = monthMap[s]
			return nil
		},
	},
	"%p": {
		Regex: `\w+`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			t.Add12InHour = s == "P"
			return nil
		},
	},
	"%I": {
		Regex: `\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			var err error
			t.Hour, err = strconv.Atoi(s)
			return err
		},
	},
	"%T": {
		Regex: `\d{2}:\d{2}:\d{2}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			v := strings.Split(s, ":")
			var err error
			t.Hour, err = strconv.Atoi(v[0])
			if err != nil {
				return err
			}

			if t.Hour >= 12 {
				t.Add12InHour = true
				t.Hour -= 12
			}

			t.Minute, err = strconv.Atoi(v[1])
			if err != nil {
				return err
			}

			t.Second, err = strconv.Atoi(v[2])
			if err != nil {
				return err
			}
			return nil
		},
	},
	"%D": {
		Regex: `\d{2}/\d{2}/\d{4}`,
		TimeParserFunction: func(s string, t *backupParsedTime) error {
			v := strings.Split(s, "/")
			var err error
			t.Day, err = strconv.Atoi(v[0])
			if err != nil {
				return err
			}
			t.Month, err = strconv.Atoi(v[1])
			if err != nil {
				return err
			}
			t.Year, err = strconv.Atoi(v[2])
			if err != nil {
				return err
			}
			return nil
		},
	},
}

type BackupHistoryInput struct {
	BackupTool      string
	BackupPath      string
	BackupFrequency string
}

type BackupHistoryOutput struct {
	MissingDates    []string
	StartDate       string
	EndDate         string
	BackupFrequency string
}

type placeholderUpdate struct {
	Regex              string
	TimeParserFunction func(string, *backupParsedTime) error
}

type backupParsedTime struct {
	Year        int
	Month       int
	Day         int
	Hour        int
	Minute      int
	Second      int
	Add12InHour bool

	Weekday int
	WeekNum int
}

func (t *backupParsedTime) GetTime() (time.Time, error) {
	if t.Year != 0 && t.Month != 0 && t.Day != 0 {
		hour := t.Hour
		if t.Add12InHour {
			hour += 12
		}
		return time.Date(t.Year, time.Month(t.Month), t.Day, hour, t.Minute, t.Second, 0, time.Local), nil
	}

	if t.Weekday != 0 && t.WeekNum != 0 && t.Year != 0 {
		days := (t.Weekday - 1) * 7
		days += t.WeekNum

		t := time.Date(t.Year, time.January, 1, 0, 0, 0, 0, time.Local)
		t = t.AddDate(0, 0, days)
		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid time")
}

func GetBackupHistory(backupPath string) ([]time.Time, error) {

	if backupPath == "" {
		return nil, fmt.Errorf("backup path is required")
	}

	patternBuilder := strings.Builder{}
	regBuilder := strings.Builder{}

	ind := []string{}

	for i := 0; i < len(backupPath); i++ {
		if backupPath[i] == '%' {
			patternBuilder.WriteString("*")
			regBuilder.WriteString(fmt.Sprintf("(%s)", mapForPrefix[string(backupPath[i:i+2])].Regex))
			ind = append(ind, string(backupPath[i:i+2]))
			i += 1
		} else {
			patternBuilder.WriteString(string(backupPath[i]))
			regBuilder.WriteString(string(backupPath[i]))
		}
	}

	if len(ind) == 0 {
		return nil, fmt.Errorf("no placeholders found in backup path")
	}

	pattern := patternBuilder.String()
	reg := regBuilder.String()

	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}

	re := regexp.MustCompile(reg)
	backupHistory := []time.Time{}

	for _, file := range files {
		if re.MatchString(file) {
			v := re.FindAllStringSubmatch(file, -1)

			backupParsedTime := backupParsedTime{}
			for i := 0; i < len(ind); i++ {
				if err := mapForPrefix[ind[i]].TimeParserFunction(v[0][i+1], &backupParsedTime); err != nil {
					return nil, fmt.Errorf("failed to parse time: %v", err)
				}
			}

			totalSize := 0
			// get size of all files in this directory
			files, err := os.ReadDir(file)
			if err != nil {
				return nil, err
			}

			for _, file := range files {
				info, err := file.Info()
				if err != nil {
					return nil, err
				}
				totalSize += int(info.Size())
			}

			if totalSize == 0 {
				continue
			}

			t, err := backupParsedTime.GetTime()
			if err != nil {
				return nil, err
			}

			backupHistory = append(backupHistory, t)
		}
	}

	return backupHistory, nil
}

// GetBackupHistoryForPgBackrest returns the history of backups using
// pgbackrest.
//
//	e.g pgbackrest info
func GetBackupHistoryForPgBackrest() ([]time.Time, error) {
	cmd := exec.Command("pgbackrest", "info")
	output, err := cmd.Output()
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("failed to run pgbackrest info: %v", err)
		}
		return nil, fmt.Errorf("failed to run pgbackrest info: %v", string(output))
	}

	dateRegex := `(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:\+\d{2}:\d{2})?`
	re := regexp.MustCompile(`timestamp\s+start/stop:\s+` + dateRegex + `\s+/\s+` + dateRegex)

	matches := re.FindAllStringSubmatch(string(output), -1)

	backupHistory := []time.Time{}
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}

		start, err := time.Parse(time.DateTime, match[1])
		if err != nil {
			return nil, err
		}
		backupHistory = append(backupHistory, start)
	}

	return backupHistory, nil
}
