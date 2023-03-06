package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/klouddb/klouddbshield/model"
)

type DescribeEventSubscription struct {
	SourceType          string `json:"SourceType"`
	SourceIdsList       any    `json:"SourceIdsList"`
	EventCategoriesList any    `json:"EventCategoriesList"`
}

func CheckEventCategoryList(sub *DescribeEventSubscription) *model.Result {
	result := &model.Result{}
	// type case sourceIDList to string array first
	eventCategoriesList, ok := sub.EventCategoriesList.([]interface{})
	if !ok {
		result.Status = "Fail"
		result.FailReason = fmt.Errorf("event category list can't be parsed %s", sub.EventCategoriesList)
		return result
	}
	eventCateGoryMap := make(map[string]bool)
	eventCateGoryMap["deletion"] = false
	eventCateGoryMap["failure"] = false
	eventCateGoryMap["failover"] = false
	eventCateGoryMap["low storage"] = false
	eventCateGoryMap["maintenance"] = false
	eventCateGoryMap["notification"] = false

	for _, eventCategory := range eventCategoriesList {

		evtCategory, ok := eventCategory.(string)
		if !ok {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("eventCategory  can't be parsed %v, type of is %s", evtCategory, reflect.TypeOf(evtCategory))
			return result
		}

		_, ok = eventCateGoryMap[evtCategory]
		if ok {
			eventCateGoryMap[evtCategory] = true
		}
	}

	for k, v := range eventCateGoryMap {
		if !v {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("event category subscription  %s is %t", k, v)
			return result
		}
	}

	result.Status = "Pass"
	return result
}

// Execute430
func Execute430(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "4.3.0"
		result.Description = "Ensure RDS event subscriptions are enabled for Instance level events"
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
		if sub.SourceType == "db-instance" {
			// all the instances type are covered && all event category list are covered for all instances
			if sub.SourceIdsList == nil {
				if sub.EventCategoriesList == nil {
					result.Status = "Pass"
					return
				} else {
					newSub := sub
					result = CheckEventCategoryList(&newSub)
					return result
				}

			}
		}
	}

	result, dbSubMap, err := GetDBMap(ctx)
	if err != nil {
		return result
	}

	var results []*model.Result
	for _, sub := range arrayOfDescribeEventSubs {
		result = CheckDescribeEventSubscription(sub, dbSubMap)
		if result.Status != "Pass" {
			result.FailReason = fmt.Errorf("event category list is missing for database %v", sub.SourceIdsList)
			return result
		}
		results = append(results, result)
	}

	if len(results) != len(dbSubMap) {
		result.FailReason = fmt.Errorf("no subscription found for some of the databases")
		result.Status = "Fail"
		return
	}

	// check if we got subscription for all databases or not
	for dbName, isSubscribed := range dbSubMap {
		if !isSubscribed {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("no subscription found for %s", dbName)
			return
		}
	}
	result.Status = "Pass"
	return result

}

func CheckDescribeEventSubscription(sub DescribeEventSubscription, dbSubMap map[string]bool) (result *model.Result) {
	result = &model.Result{}
	if sub.SourceType != "db-instance" {
		return result
	}
	// all the instances type are covered && all event category list are covered for all instances
	if sub.SourceIdsList != nil {
		// type case sourceIDList to string array first
		sourceIDs, ok := sub.SourceIdsList.([]interface{})
		if !ok {
			result.Status = "Fail"
			result.FailReason = fmt.Errorf("source ID List can't be parsed %s, type of is %s", sub.SourceIdsList, reflect.TypeOf(sub.SourceIdsList))
			return
		}
		for _, sourceID := range sourceIDs {
			srcID, ok := sourceID.(string)
			if !ok {
				result.Status = "Fail"
				result.FailReason = fmt.Errorf("source ID  can't be parsed %v, type of is %s", sourceID, reflect.TypeOf(sourceID))
				return
			}
			dbSubMap[srcID] = true
		}
	} else {
		result.Status = "Pass"
	}
	result = CheckEventCategoryList(&sub)
	return result

}
