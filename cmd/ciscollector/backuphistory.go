package main

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/pkg/backuphistory"
)

type backupHistory struct {
	backupHistoryInput backuphistory.BackupHistoryInput
	htmlReportHelper   *htmlreport.HtmlReportHelper
}

func newBackupHistory(backupHistoryInput backuphistory.BackupHistoryInput, htmlReportHelper *htmlreport.HtmlReportHelper) *backupHistory {
	return &backupHistory{
		backupHistoryInput: backupHistoryInput,
		htmlReportHelper:   htmlReportHelper,
	}
}

func (h *backupHistory) cronProcess(ctx context.Context) error {
	return h.run(ctx)
}

func (h *backupHistory) run(_ context.Context) error {
	if h.backupHistoryInput.BackupFrequency == "" {
		return fmt.Errorf("backup frequency is required")
	}

	var backupHistory []time.Time
	var err error

	switch h.backupHistoryInput.BackupTool {
	case "pgbackrest":
		backupHistory, err = backuphistory.GetBackupHistoryForPgBackrest()
		if err != nil {
			return err
		}
	case "pg_dump", "pg_dumpall", "pg_basebackup":
		backupHistory, err = backuphistory.GetBackupHistory(h.backupHistoryInput.BackupPath)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported backup tool: %s", h.backupHistoryInput.BackupTool)
	}

	if len(backupHistory) == 0 {
		return fmt.Errorf("no backup history found")
	} else if len(backupHistory) == 1 {
		return fmt.Errorf("only one backup history found")
	}

	sort.Slice(backupHistory, func(i, j int) bool {
		return backupHistory[i].After(backupHistory[j])
	})

	missingDates := []string{}
	previousDate := backupHistory[len(backupHistory)-1]

	if h.backupHistoryInput.BackupFrequency == "daily" {
		for i := len(backupHistory) - 2; i >= 0; i-- {
			if previousDate.Format(time.DateOnly) == backupHistory[i].Format(time.DateOnly) {
				continue
			}

			nextDate := previousDate.AddDate(0, 0, 1)
			for nextDate.Format(time.DateOnly) != backupHistory[i].Format(time.DateOnly) {
				missingDates = append(missingDates, nextDate.Format(time.DateOnly))
				nextDate = nextDate.AddDate(0, 0, 1)
			}

			previousDate = backupHistory[i]
		}
	} else if h.backupHistoryInput.BackupFrequency == "weekly" {
		for i := len(backupHistory) - 2; i >= 0; i-- {
			previousYear, previousWeek := previousDate.ISOWeek()
			currentYear, currentWeek := backupHistory[i].ISOWeek()

			if previousYear == currentYear && previousWeek == currentWeek {
				continue
			}

			nextDate := previousDate.AddDate(0, 0, 7)
			nextDateYear, nextDateWeek := nextDate.ISOWeek()
			for nextDateYear != currentYear || nextDateWeek != currentWeek {
				missingDates = append(missingDates, fmt.Sprintf("year %d - week %d", nextDateYear, nextDateWeek))
				nextDate = nextDate.AddDate(0, 0, 7)
				nextDateYear, nextDateWeek = nextDate.ISOWeek()
			}

			previousDate = backupHistory[i]
		}
	} else if h.backupHistoryInput.BackupFrequency == "monthly" {
		for i := len(backupHistory) - 2; i >= 0; i-- {
			if previousDate.Format("2006-01") == backupHistory[i].Format("2006-01") {
				continue
			}

			nextDate := previousDate.AddDate(0, 1, 0)
			for nextDate.Format("2006-01") != backupHistory[i].Format("2006-01") {
				missingDates = append(missingDates, nextDate.Format("2006-01"))
				nextDate = nextDate.AddDate(0, 1, 0)
			}

			previousDate = backupHistory[i]
		}
	} else {
		return fmt.Errorf("unsupported backup frequency: %s", h.backupHistoryInput.BackupFrequency)
	}

	uniqueMissingDates := []string{}
	for _, v := range missingDates {
		if !slices.Contains(uniqueMissingDates, v) {
			uniqueMissingDates = append(uniqueMissingDates, v)
		}
	}

	output := backuphistory.BackupHistoryOutput{
		MissingDates:    uniqueMissingDates,
		StartDate:       backupHistory[len(backupHistory)-1].Format("2006-01-02"),
		EndDate:         backupHistory[0].Format("2006-01-02"),
		BackupFrequency: h.backupHistoryInput.BackupFrequency,
	}

	backuphistory.PrintBackupHistory(output)

	h.htmlReportHelper.RegisterBackupHistory(output)

	return nil
}
