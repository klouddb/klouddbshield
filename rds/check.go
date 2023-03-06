package rds

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/klouddb/klouddbshield/model"
)

func fixFailReason(result *model.Result) *model.Result {
	if result == nil {
		return result
	}
	err, ok := result.FailReason.(error)
	if !ok {
		return result
	}
	result.FailReason = err.Error()
	return result
}

func PerformAllChecks(ctx context.Context) []*model.Result {
	var listOfResult []*model.Result

	// 2.3.1
	result := Execute231(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute232(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute233(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute350(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute380(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute420(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute430(ctx)
	listOfResult = append(listOfResult, result)

	result = Execute440(ctx)
	listOfResult = append(listOfResult, result)

	CalculateScore(listOfResult)
	return listOfResult
}

func CalculateScore(listOfResult []*model.Result) map[int]*model.Status {
	log.Println("the number of results are", len(listOfResult))

	score := make(map[int]*model.Status, 4)

	for i := 0; i <= 4; i++ {
		score[i] = new(model.Status)
	}

	for _, result := range listOfResult {
		if result == nil {
			continue
		}
		if strings.HasPrefix(result.Control, "1") {
			if result.Status == "Pass" {
				score[1].Pass += 1
				score[0].Pass += 1
			} else {
				score[1].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "2") {
			if result.Status == "Pass" {
				score[2].Pass += 1
				score[0].Pass += 1
			} else {
				score[2].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "3") {
			if result.Status == "Pass" {
				score[3].Pass += 1
				score[0].Pass += 1
			} else {
				score[3].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "4") {
			if result.Status == "Pass" {
				score[4].Pass += 1
				score[0].Pass += 1
			} else {
				score[4].Fail += 1
				score[0].Fail += 1
			}
		}
	}
	PrintScore(score)
	return score
}
func PrintScore(score map[int]*model.Status) {
	format := []string{
		"Section 1  - Doesn't exist          - %d/%d  - %.2f%%\n",
		"Section 2  - RDS Instance encryption Minor and Publish Access Checks - %d/%d - %.2f%%\n",
		"Section 3  - RDS Instance AZ check and retention policy     - %d/%d  - %.2f%%\n",
		"Section 4  - RDS Instance SNS Subscription                    - %d/%d  - %.2f%%\n",
	}
	for key, value := range format {
		total := (score[key+1].Pass + score[key+1].Fail)
		if total == 0 {
			continue
		}
		fmt.Printf(value,
			score[key+1].Pass,
			(score[key+1].Pass + score[key+1].Fail),
			(float64(score[key+1].Pass) / float64(total) * 100),
		)
	}
	fmt.Printf("Overall Score - %d/%d - %.2f%%\n",
		score[0].Pass,
		(score[0].Pass + score[0].Fail),
		(float64(score[0].Pass) / float64((score[0].Pass + score[0].Fail)) * 100),
	)

}
