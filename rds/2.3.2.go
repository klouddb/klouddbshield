package rds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

// Execute232 executed 2.3.2
func Execute232(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "2.3.2"
		result.Description = "Ensure that auto minor version upgrade is enabled for RDS instances"
		result = fixFailReason(result)
	}()

	result, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-db-instances  --query 'DBInstances[*].DBInstanceIdentifier'")
	if err != nil {
		result.Status = "Fail"
		result.FailReason = fmt.Errorf("error executing command %s", err)
		return result
	}

	var arrayOfDataBases []string
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDataBases)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = fmt.Errorf("error un marshalling %s", err)
		return
	}

	for _, dbName := range arrayOfDataBases {
		result, cmdOutput, err = ExecRdsCommand(ctx, fmt.Sprintf(`aws rds describe-db-instances --db-instance-identifier  "%s" --query 'DBInstances[*].AutoMinorVersionUpgrade'`, dbName))
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("error executing command %s", err)
			return result
		}

		var arrayOfBooleans []bool
		err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfBooleans)
		if err != nil {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("error un marshalling %s", err)
			return
		}
		if len(arrayOfBooleans) != 1 {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("the len of the databases to verify is not correct")
			return
		}
		if !arrayOfBooleans[0] {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("auto minor version upgrade is not enabled for instance %s", dbName)
			return
		}
	}
	result.Status = "Pass"
	return result

}
