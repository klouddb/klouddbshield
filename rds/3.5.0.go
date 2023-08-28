package rds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

type MultiAZ struct {
	MultiAZ              bool
	DBInstanceIdentifier string
}

// Execute350
func Execute350(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "3.5.0"
		result.Title = "Multi-AZ check"
		result = fixFailReason(result)
	}()

	result, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-db-instances  --query 'DBInstances[*].{MultiAZ:MultiAZ, DBInstanceIdentifier:DBInstanceIdentifier}'")
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error executing command %s", err)
		return result
	}

	var arrayOfDataBases []MultiAZ
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDataBases)
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error un marshalling %s", err)
		return
	}
	printer := NewRDSInstancePrinter()

	for _, multiAZDB := range arrayOfDataBases {

		if !multiAZDB.MultiAZ {
			result.Status = Fail
			// result.FailReason = fmt.Errorf("data base %s is not multiAZ", multiAZDB.DBInstanceIdentifier)
			printer.AddInstance(multiAZDB.DBInstanceIdentifier, "Fail", fmt.Sprintf("%t", multiAZDB.MultiAZ))
			continue
		} else {
			printer.AddInstance(multiAZDB.DBInstanceIdentifier, "Pass", fmt.Sprintf("%t", multiAZDB.MultiAZ))
		}
	}
	if result.Status != Fail {
		result.Status = Pass
	}
	result.FailReason = printer.Print()
	return result

}
