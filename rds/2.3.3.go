package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/klouddb/klouddbshield/model"
)

// Execute233 executed 2.3.3
func Execute233(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "2.3.3"
		result.Description = "Ensure that public address is not given to RDS instance"
		result = fixFailReason(result)
	}()

	result, dbMap, err := GetDBMap(ctx)
	if err != nil {
		return result
	}
	printer := NewTablePrinter()
	mutex := &sync.Mutex{}
	gp := NewGoPool(ctx)

	log.Printf("\n Executing 2.3.3 You have %d instances in this region - This scan might take sometime .. Rough estimate is %f", len(dbMap), float64(len(dbMap))*(timeToRunAWSCommand.Seconds()))

	var listOfResult []*model.Result
	for dbName := range dbMap {
		gp.AddJob("ExecutePerDB", ExecutePerDB, GetPublicAccessStatusOfDB, dbName, printer, &listOfResult, mutex)
	}
	// wait for all go routines to be done
	gp.WaitGroup().Wait()
	gp.ShutDown(true, time.Second)

	for _, result := range listOfResult {
		if result.Status == Fail {
			result.FailReason = printer.Print()
			return result
		}
	}
	result.Status = Pass
	return result

}

func GetPublicAccessStatusOfDB(ctx context.Context, dbName string, printer *tablePrinter) *model.Result {
	result, cmdOutput, err := ExecRdsCommand(ctx, fmt.Sprintf(`aws rds describe-db-instances --db-instance-identifier  "%s" --query 'DBInstances[*].PubliclyAccessible'`, dbName))
	if err != nil {
		result.Status = Fail
		printer.AddInstance(dbName, "Fail", fmt.Errorf("error executing command %s", err).Error())
		return result
	}

	var arrayOfBooleans []bool
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfBooleans)
	if err != nil {
		result.Status = Fail
		printer.AddInstance(dbName, "Fail", fmt.Errorf("error un marshalling %s", err).Error())
		return result
	}
	if len(arrayOfBooleans) != 1 {
		result.Status = Fail
		printer.AddInstance(dbName, "Fail", fmt.Errorf("the len of the databases to verify is not correct").Error())
		return result
	}
	if arrayOfBooleans[0] {
		result.Status = Fail
		printer.AddInstance(dbName, "Fail", fmt.Sprintf("%t", arrayOfBooleans[0]))
		return result
	} else {
		result.Status = Pass
		printer.AddInstance(dbName, "Pass", fmt.Sprintf("%t", arrayOfBooleans[0]))
	}
	return result
}
