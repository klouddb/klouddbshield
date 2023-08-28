package rds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

type BackupRetention struct {
	BackupRetentionPeriod int    `json:"BackupRetentionPeriod"`
	DBInstanceIdentifier  string `json:"DBInstanceIdentifier"`
}

// Execute380
func Execute380(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "3.8.0"
		result.Title = "Ensure Relational Database Service backup retention policy is set"
		result = fixFailReason(result)
	}()

	result, cmdOutput, err := ExecRdsCommand(ctx, `aws rds describe-db-instances --filters --query "DBInstances[*].{BackupRetentionPeriod:BackupRetentionPeriod,DBInstanceIdentifier:DBInstanceIdentifier}"`)
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error executing command %s", err)
		return result
	}

	var backupRetentionValues []BackupRetention
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &backupRetentionValues)
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error un marshalling cmdOutput.StdOut: %s, error :%s", cmdOutput.StdOut, err)
		return
	}
	printer := NewRDSInstancePrinter()
	for _, multiAZDB := range backupRetentionValues {

		if multiAZDB.BackupRetentionPeriod < 7 {
			result.Status = Fail
			// result.FailReason = fmt.Errorf("data base %s have retention period less than 7", multiAZDB.DBInstanceIdentifier)
			printer.AddInstance(multiAZDB.DBInstanceIdentifier, "Fail", fmt.Sprintf("%d", multiAZDB.BackupRetentionPeriod))
			continue
		} else {
			printer.AddInstance(multiAZDB.DBInstanceIdentifier, "Pass", fmt.Sprintf("%d", multiAZDB.BackupRetentionPeriod))
		}
	}
	if result.Status != Fail {
		result.Status = Pass
	}
	result.FailReason = printer.Print()
	return result

}
