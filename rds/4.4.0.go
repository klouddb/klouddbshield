package rds

import (
	"context"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

func CheckForAllSourceTypesAllEventCategoriesDBSecurityGroup(ctx context.Context, sub *EventSubscription) bool {
	if sub == nil {
		return false
	}
	// if sub.Status != "active" {
	// 	return false
	// }

	sourceIDList, sourceIDlistNil := GetSourceIDList(sub)
	if len(sourceIDList) > 0 {
		return false
	}

	eventCategoryList, eventCategoryListNil := GetEventCategoryList(sub)
	if len(eventCategoryList) > 0 {
		return false
	}

	if sub.SourceType == "" {
		if sourceIDlistNil && eventCategoryListNil {
			return true
		} else if !sourceIDlistNil {
			return false
		} else if !eventCategoryListNil {
			return false
		}
	}

	if sub.SourceType == DBSecurityGroup {
		if sourceIDlistNil && eventCategoryListNil {
			return true
		} else if !sourceIDlistNil {
			return false
		} else if !eventCategoryListNil {
			return false
		}
	}

	return false
}

// Execute440
func Execute440(ctx context.Context) (result *model.Result) {

	if result == nil {
		result = &model.Result{}
	}
	dbResultMap := make(map[string]*model.CaseResult)
	result.CaseFailReason = dbResultMap
	if DataBaseGetter == nil {
		DataBaseGetter = &AWSDB{}
	}

	_, _, err := DataBaseGetter.GetDBMap(ctx)
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Sprintf("error getting databases %s", err)
		return result
	}

	printer := NewRDSInstancePrinter()
	result = &model.Result{}
	defer func() {
		result.Control = "4.4.0"
		result.Title = "Ensure RDS event subscriptions are enabled for DB security groups"
		result.FailReason = printer.Print()
		if result.Status == Manual {
			result.Status = Manual
		}
	}()

	if SubGetter == nil {
		SubGetter = &AWSSubGetter{}
	}
	arrayOfDescribeEventSubs, err := SubGetter.GetEventSubscription(ctx)
	if err != nil || arrayOfDescribeEventSubs == nil {
		result.Status = Fail
		result.FailReason = fmt.Sprintf("error getting subscriptions %s", err)
		return
	}

	var finalSourceIDList []string
	// first we make sure we have subscription for all. if we are this far means either we got sourceIDlist is nil and event category is not empty
	// or sourceIDlist is not nil and we got some records.
	for _, sub := range arrayOfDescribeEventSubs {
		// test case2 and test case 4 are covered here
		isEnabledForAll := CheckForAllSourceTypesAllEventCategoriesDBSecurityGroup(ctx, &sub)
		if isEnabledForAll {
			result.Status = Pass
			return
		}

		arrayOfSourceIDList, sourceIDListNil := GetSourceIDList(&sub)
		if sourceIDListNil {
			continue
		}
		finalSourceIDList = append(finalSourceIDList, arrayOfSourceIDList...) ////nolint:staticcheck
	}

	// if the number of subscriptions it is showing is greater than 1 but we know it hasn't passed before we need manual check
	if len(arrayOfDescribeEventSubs) > 1 {
		printer.AddInstance("Multi Subscription found", Manual, "Manual check needed")
		result.Status = Manual
		return
	}

	result.Status = Fail
	result.FailReason = "no subscriptions for security group"
	printer.AddInstance("No subscriptions found for security group", Fail, "Please add subscriptions for security group")
	return result

}
