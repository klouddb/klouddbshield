package cron

import (
	"time"

	"github.com/robfig/cron"
)

func getNextTwoOccurrences(cronExpr string) ([]time.Time, error) {
	schedule, err := cron.ParseStandard(cronExpr)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var occurrences []time.Time

	next := schedule.Next(now)
	occurrences = append(occurrences, next)

	// Get the second occurrence
	next = schedule.Next(next)
	occurrences = append(occurrences, next)

	return occurrences, nil
}

func IsLessThan24Hours(cronExpr string) (bool, error) {
	occurrences, err := getNextTwoOccurrences(cronExpr)
	if err != nil {
		return false, err
	}

	// Compare the difference between the two occurrences
	duration := occurrences[1].Sub(occurrences[0])
	return duration >= 24*time.Hour, nil
}

func GetPreviousExecutionTime(cronExpr string) (time.Time, error) {
	occurrences, err := getNextTwoOccurrences(cronExpr)
	if err != nil {
		return time.Time{}, err
	}

	return time.Now().Add(occurrences[0].Sub(occurrences[1])), nil
}
