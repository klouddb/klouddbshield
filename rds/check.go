package rds

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/klouddb/klouddbshield/model"
)

type Execute func(context.Context) *model.Result

func PerformAllChecks(ctx context.Context) []*model.Result {

	listOfExecuteFuncs := [...]Execute{
		Execute231,
		Execute232,
		Execute233,
		Execute350,
		Execute380,
		Execute420,
		Execute430,
		Execute440,
	}
	mutex := &sync.Mutex{}

	gp := NewGoPool(context.Background())
	fn := func(ctx context.Context, args ...interface{}) error {
		select {
		case <-ctx.Done():
			return nil
		default:
			if len(args) != 3 {
				log.Println("number of arguments passed is not 3")
				return nil
			}
			executeFunc, ok := args[0].(Execute)
			if !ok {
				log.Println("first argument cant be parsed to execute func")
				return nil
			}
			listOfResult, ok := args[1].(*[]*model.Result)
			if !ok {
				log.Println("first argument cant be parsed to array of results")
				return nil
			}
			lock, ok := args[2].(*sync.Mutex)
			if !ok {
				log.Println("first argument cant be parsed to mutex")
				return nil
			}
			// start := time.Now()
			result := executeFunc(ctx)
			lock.Lock()
			*listOfResult = append(*listOfResult, result)
			lock.Unlock()
			// timeTaken := time.Since(start)
			// log.Println("time taken to execute", fmt.Sprintf("%T", executeFunc), "is", timeTaken)
			return nil
		}
	}
	var listOfResult []*model.Result
	for _, execFunc := range listOfExecuteFuncs {
		gp.AddJob("ExecFunc", fn, execFunc, &listOfResult, mutex)
	}
	// wait for all go routines to be done
	gp.WaitGroup().Wait()
	gp.ShutDown(true, time.Second)

	// CalculateScore(listOfResult)
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
			if result.Status == Pass {
				score[1].Pass += 1
				score[0].Pass += 1
			} else {
				score[1].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "2") {
			if result.Status == Pass {
				score[2].Pass += 1
				score[0].Pass += 1
			} else {
				score[2].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "3") {
			if result.Status == Pass {
				score[3].Pass += 1
				score[0].Pass += 1
			} else {
				score[3].Fail += 1
				score[0].Fail += 1
			}
		}
		if strings.HasPrefix(result.Control, "4") {
			if result.Status == Pass {
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

func ConvertToTable(listOfResults []*model.Result) string {
	sort.Slice(listOfResults, func(i, j int) bool {
		v1, err := version.NewVersion(listOfResults[i].Control)
		if err != nil {
			return false
		}
		v2, err := version.NewVersion(listOfResults[j].Control)
		if err != nil {
			return false
		}
		// Comparison example. There is also GreaterThan, Equal, and just
		// a simple Compare that returns an int allowing easy >=, <=, etc.
		return v1.LessThan(v2)
	})

	// sb := strings.Builder{}
	// for _, result := range listOfResults {
	// 	sb.WriteString("\n\n")
	// 	sp := NewSectionPrinter(result)
	// 	sb.WriteString(sp.Print())
	// 	sb.WriteString("\n\n")
	// }
	// return sb.String()

	rdsPrinter := NewRDSPrinter(listOfResults)
	return rdsPrinter.Print()
}

func ConvertToMainTable(listOfResults []*model.Result) string {
	sort.Slice(listOfResults, func(i, j int) bool {
		v1, err := version.NewVersion(listOfResults[i].Control)
		if err != nil {
			return false
		}
		v2, err := version.NewVersion(listOfResults[j].Control)
		if err != nil {
			return false
		}
		// Comparison example. There is also GreaterThan, Equal, and just
		// a simple Compare that returns an int allowing easy >=, <=, etc.
		return v1.LessThan(v2)
	})

	rdsPrinter := NewRDSPrinter(listOfResults)
	return rdsPrinter.SectionPrint()
}
