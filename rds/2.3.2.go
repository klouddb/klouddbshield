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

// Execute232 executed 2.3.2
func Execute232(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "2.3.2"
		result.Title = "Ensure that auto minor version upgrade is enabled for RDS instances"
	}()

	result, dbMap, err := GetDBMap(ctx)
	if err != nil {
		return result
	}
	printer := NewRDSInstancePrinter()
	mutex := &sync.Mutex{}
	gp := NewGoPool(ctx)

	log.Printf("\n Executing 2.3.2 You have %d instances in this region - This scan might take sometime .. Rough estimate is %f", len(dbMap), float64(len(dbMap))*(timeToRunAWSCommand.Seconds()))

	var listOfResult []*model.Result
	for dbName := range dbMap {
		gp.AddJob("ExecutePerDB", ExecutePerDB, GetAutoMinorVersionOfDB, dbName, printer, &listOfResult, mutex)
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

func GetAutoMinorVersionOfDB(ctx context.Context, dbName string, printer *rdsInstancePrinter) *model.Result {
	result, cmdOutput, err := ExecRdsCommand(ctx, fmt.Sprintf(`aws rds describe-db-instances --db-instance-identifier  "%s" --query 'DBInstances[*].AutoMinorVersionUpgrade'`, dbName))
	if err != nil {
		result.Status = Fail
		printer.AddInstance(dbName, "Fail", fmt.Errorf("error executing command %s", err).Error())
	}

	var arrayOfBooleans []bool
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfBooleans)
	if err != nil {
		result.Status = Fail

		printer.AddInstance(dbName, "Fail", fmt.Errorf("error un marshalling %s", err).Error())
	}
	if len(arrayOfBooleans) != 1 {
		result.Status = Fail

		printer.AddInstance(dbName, "Fail", fmt.Errorf("the len of the databases to verify is not correct").Error())
	}
	if !arrayOfBooleans[0] {
		result.Status = Fail
		result.FailReason = fmt.Sprintf("auto minor version upgrade is not enabled for instance %s", dbName)
		printer.AddInstance(dbName, "Fail", fmt.Sprintf("%t", arrayOfBooleans[0]))
	} else {
		printer.AddInstance(dbName, "Pass", fmt.Sprintf("%t", arrayOfBooleans[0]))
	}
	return result
}
