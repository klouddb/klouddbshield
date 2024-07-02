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

const Pass = "Pass"
const Fail = "Fail"
const Manual = "Manual"

func ExecutePerDB(ctx context.Context, args ...interface{}) error {

	select {
	case <-ctx.Done():
		return nil
	default:
		if len(args) != 5 {
			log.Println("number of arguments passed is not 3")
			return nil
		}

		dbFunc, ok := args[0].(func(context.Context, string, *rdsInstancePrinter) *model.Result)
		if !ok {
			log.Println("first argument cant be parsed to dbStatus func")
			return nil
		}

		dbName, ok := args[1].(string)
		if !ok {
			log.Println("second argument cant be parsed to string")
			return nil
		}
		printer, ok := args[2].(*rdsInstancePrinter)
		if !ok {
			log.Println("third argument cant be parsed to table printer")
			return nil
		}

		listOfResult, ok := args[3].(*[]*model.Result)
		if !ok {
			log.Println("fourth argument cant be parsed to array of results")
			return nil
		}

		lock, ok := args[4].(*sync.Mutex)
		if !ok {
			log.Println("fifth argument cant be parsed to mutex")
			return nil
		}

		result := dbFunc(ctx, dbName, printer)
		lock.Lock()
		*listOfResult = append(*listOfResult, result)
		lock.Unlock()
		return nil
	}
}

// Execute231 executed 2.3.1
func Execute231(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "2.3.1"
		result.Title = "Ensure that encryption is enabled for RDS instances"

	}()

	result, dbMap, err := GetDBMap(ctx)
	if err != nil {
		return result
	}
	printer := NewRDSInstancePrinter()
	mutex := &sync.Mutex{}
	gp := NewGoPool(ctx)

	log.Printf("\n Executing 2.3.1 You have %d instances in this region - This scan might take sometime .. Rough estimate is %f", len(dbMap), float64(len(dbMap))*(timeToRunAWSCommand.Seconds()))

	// start := time.Now()

	var listOfResult []*model.Result
	for dbName := range dbMap {
		gp.AddJob("ExecutePerDB", ExecutePerDB, GetEncryptionStatusOfDB, dbName, printer, &listOfResult, mutex)
	}
	// wait for all go routines to be done
	gp.WaitGroup().Wait()
	gp.ShutDown(true, time.Second)

	// timeTaken := time.Since(start)
	// log.Println("Time taken to execute 2.3.1", timeTaken.Seconds(), "seconds")

	for _, result := range listOfResult {
		if result.Status == Fail {
			result.FailReason = printer.Print()
			return result
		}
	}
	result.Status = Pass
	return result

}
func GetEncryptionStatusOfDB2(ctx context.Context) *model.Result {
	return nil
}

func GetEncryptionStatusOfDB(ctx context.Context, dbName string, printer *rdsInstancePrinter) *model.Result {
	result, cmdOutput, err := ExecRdsCommand(ctx, fmt.Sprintf(`aws rds describe-db-instances  --db-instance-identifier "%s" --query 'DBInstances[*].StorageEncrypted'`, dbName))
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
		printer.AddInstance(dbName, "Fail", fmt.Errorf("the len of the databases storage encrypted to verify is not correct").Error())
	}
	if !arrayOfBooleans[0] {
		result.Status = Fail
		printer.AddInstance(dbName, "Fail", fmt.Sprintf("%t", arrayOfBooleans[0]))
	} else {
		printer.AddInstance(dbName, "Pass", fmt.Sprintf("%t", arrayOfBooleans[0]))
	}
	return result
}
