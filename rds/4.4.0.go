package rds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

// Execute440
func Execute440(ctx context.Context) (result *model.Result) {
	result = &model.Result{}
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "4.4.0"
		result.Description = "Ensure RDS event subscriptions are enabled for DB security groups"
		result = fixFailReason(result)
	}()

	result, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-event-subscriptions --query 'EventSubscriptionsList[*].{SourceType:SourceType, SourceIdsList:SourceIdsList, EventCategoriesList:EventCategoriesList}'")
	if err != nil {
		result.Status = "Fail"
		result.FailReason = fmt.Errorf("error executing command %s", err)
		return result
	}

	var arrayOfDescribeEventSubs []DescribeEventSubscription
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDescribeEventSubs)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = fmt.Errorf("error un marshalling %s", err)
		return
	}

	if len(arrayOfDescribeEventSubs) == 0 {
		result.Status = "Fail"
		result.FailReason = "no describe event subscriptions exist"
		return
	}

	for _, sub := range arrayOfDescribeEventSubs {
		if sub.SourceType == "db-security-group" {
			// all the instances type are covered && all event category list are covered for all instances
			if sub.SourceIdsList == nil {
				result.Status = "Pass"
				return
			}
		}
	}
	result.Status = "Fail"
	result.FailReason = "no subscriptions for security group"
	return result

}
