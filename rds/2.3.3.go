package rds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

// Execute232 executed 2.3.2
func Execute233(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "2.3.3"
		result.Description = "Ensure that public address is not given to RDS instance"
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
		result, cmdOutput, err = ExecRdsCommand(ctx, fmt.Sprintf(`aws rds describe-db-instances --db-instance-identifier  "%s" --query 'DBInstances[*].PubliclyAccessible'`, dbName))
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
		if arrayOfBooleans[0] {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("public access is enabled for database data base %s ", dbName)
			return
		}
	}
	result.Status = "Pass"
	return result

}
