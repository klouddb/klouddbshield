package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/klouddb/klouddbshield/model"
)

var (
	ErrEmptySubscriptions = fmt.Errorf("no event subscriptions present")
)

const (
	DBInstanceType    = "db-instance"
	DBSecurityGroup   = "db-security-group"
	ManualCheckNeeded = "manual check needed"
)

var SubGetter SubscriptionGetter
var DataBaseGetter DBGetter

type DBGetter interface {
	GetDBMap(ctx context.Context) (*model.Result, map[string]bool, error)
}

type AWSDB struct {
}

func (a *AWSDB) GetDBMap(ctx context.Context) (*model.Result, map[string]bool, error) {
	return GetDBMap(ctx)
}

type SubscriptionGetter interface {
	GetEventSubscription(ctx context.Context) ([]EventSubscription, error)
}

type AWSSubGetter struct {
}

func (s *AWSSubGetter) GetEventSubscription(ctx context.Context) ([]EventSubscription, error) {
	_, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-event-subscriptions --query 'EventSubscriptionsList[*].{SourceType:SourceType, SourceIdsList:SourceIdsList, EventCategoriesList:EventCategoriesList}'")
	if err != nil {
		return nil, fmt.Errorf("error executing command %s", err)
	}

	var arrayOfDescribeEventSubs []EventSubscription
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDescribeEventSubs)
	if err != nil {
		return nil, err
	}

	if len(arrayOfDescribeEventSubs) == 0 {
		return nil, ErrEmptySubscriptions
	}
	return arrayOfDescribeEventSubs, nil
}

type DescribeEventSubscription struct {
	SourceType          string `json:"SourceType"`
	SourceIdsList       any    `json:"SourceIdsList"`
	EventCategoriesList any    `json:"EventCategoriesList"`
	Status              string `json:"Status"`
}

func CheckForAllSourceTypesAllEventCategoriesDBInstances(ctx context.Context, sub *EventSubscription) bool {
	if sub == nil {
		return false
	}

	// for cases where we get output like this because of  aws rds describe-event-subscriptions --query 'EventSubscriptionsList[*].{SourceType:SourceType, SourceIdsList:SourceIdsList, EventCategoriesList:EventCategoriesList}'
	// we shouldn't be checking status as active
	// {
	//     "SourceType": "db-instance",
	//     "SourceIdsList": null,
	//     "EventCategoriesList": null
	// }

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

	if sub.SourceType == DBInstanceType {
		if sourceIDlistNil && eventCategoryListNil {
			// log.Println("source type list is nil")
			return true
		} else if !sourceIDlistNil {
			// log.Println("source type list is not nil", sourceIDlistNil)
			return false
		} else if !eventCategoryListNil {
			// log.Println("event category list not nil", eventCategoryListNil)
			return false
		}
	}

	return false
}

// Execute430 ...
func Execute430(ctx context.Context) (result *model.Result) {
	if result == nil {
		result = &model.Result{}
	}
	dbResultMap := make(map[string]*model.CaseResult)
	result.CaseFailReason = dbResultMap
	if DataBaseGetter == nil {
		DataBaseGetter = &AWSDB{}
	}

	_, dbSubMap, err := DataBaseGetter.GetDBMap(ctx)
	if err != nil {
		// log.Println("error getting database", err)
		result.Status = Fail
		result.FailReason = fmt.Errorf("error getting databases %s", err)
		return result
	}

	// assign fail reason to empty
	for dbName := range dbSubMap {
		dbResultMap[dbName] = model.NewCaseResult(dbName)
	}

	printer := NewRDSInstancePrinter()
	defer func() {
		result.Control = "4.3.0"
		result.Title = "Ensure RDS event subscriptions are enabled for Instance level events"
		result = fixFailReason(result)

		for dbName, _ := range dbSubMap {
			_, ok := dbResultMap[dbName]
			if !ok {
				dbResultMap[dbName] = model.NewCaseResult(dbName)
			}
			if result.Status == Pass {
				dbResultMap[dbName].Reason = fmt.Sprintf("subscription found for %s", dbName)
				dbResultMap[dbName].Status = Pass
			}
			if result.Status == Manual {
				dbResultMap[dbName].Reason = fmt.Sprintf(ManualCheckNeeded+" %s", dbName)
				dbResultMap[dbName].Status = Manual
			}
			printer.AddInstance(dbName, dbResultMap[dbName].Status, dbResultMap[dbName].Reason)
		}
		result.FailReason = printer.Print()
	}()

	if SubGetter == nil {
		SubGetter = &AWSSubGetter{}
	}
	arrayOfDescribeEventSubs, err := SubGetter.GetEventSubscription(ctx)
	if err != nil || arrayOfDescribeEventSubs == nil {
		// log.Println("error getting database", err, arrayOfDescribeEventSubs)
		result.Status = Fail
		result.FailReason = fmt.Errorf("error getting subscriptions %s", err)
		return
	}

	log.Println("the event subscription we got is", arrayOfDescribeEventSubs)

	// var finalSourceIDList []string
	// first we make sure we have subscription for all. if we are this far means either we got sourceIDlist is nil and event category is not empty
	// or sourceIDlist is not nil and we got some records.
	for _, sub := range arrayOfDescribeEventSubs {
		// test case2 and test case 4 are covered here
		isEnabledForAll := CheckForAllSourceTypesAllEventCategoriesDBInstances(ctx, &sub)
		if isEnabledForAll {
			result.Status = Pass
			return
		}

		_, sourceIDListNil := GetSourceIDList(&sub)
		if sourceIDListNil {
			continue
		}
		// log.Println("adding sourceID list", arrayOfSourceIDList)
		// finalSourceIDList = append(finalSourceIDList, arrayOfSourceIDList...)
	}

	// if the number of subscriptions it is showing is greater than 1 but we know it hasn't passed before we need manual check
	if len(arrayOfDescribeEventSubs) > 1 {
		printer.AddInstance("Multi Subscription found", Manual, "Manual check needed")
		result.Status = Manual
		return
	}

	// because by here we confirmed only one remains
	subToCheck := arrayOfDescribeEventSubs[0]

	if subToCheck.SourceType != DBInstanceType {
		printer.AddInstance("Source type is not Instance type", Fail, subToCheck.SourceType)
		result.Status = Fail
		return
	}

	arrayOfSourceIDList, sourceIDListNil := GetSourceIDList(&subToCheck)

	// if sourceIDlist is nil we have subscription for all
	if sourceIDListNil {
		for srcID, _ := range dbSubMap {
			arrayOfSourceIDList = append(arrayOfSourceIDList, srcID)
		}
	}

	// here set for how many we have subscription. remaining set subscription is false
	for _, srcID := range arrayOfSourceIDList {
		dbResult := model.NewCaseResult(srcID)
		dbResult.Status = Pass
		dbResult.Reason = fmt.Sprintf("subscription found for %s", srcID)
		dbResultMap[srcID] = dbResult
	}

	if len(arrayOfSourceIDList) == len(dbSubMap) {
		result.Status = Pass
	} else {
		result.Status = Fail
	}

	// if !sourceIDListNil && len(arrayOfSourceIDList) != len(dbSubMap) {
	// 	// log.Println("source ID list not equal to submap")
	// 	result.FailReason = fmt.Errorf("no subscription found for %d of the databases, sourceIDList: %s", len(dbSubMap)-len(arrayOfSourceIDList), arrayOfSourceIDList)
	// 	result.Status = Fail
	// 	return
	// }

	eventCategoryList, eventCategoryListNil := GetEventCategoryList(&subToCheck)
	if eventCategoryListNil {
		if result.Status != Fail {
			result.Status = Pass
		}
		return
	}

	if len(eventCategoryList) > 0 {
		eventCateGoryMap := make(map[string]bool)
		eventCateGoryMap["deletion"] = false
		eventCateGoryMap["failure"] = false
		eventCateGoryMap["failover"] = false
		eventCateGoryMap["low storage"] = false
		eventCateGoryMap["maintenance"] = false
		eventCateGoryMap["notification"] = false

		for _, eventCategory := range eventCategoryList {
			_, ok := eventCateGoryMap[eventCategory]
			if ok {
				eventCateGoryMap[eventCategory] = true
			}
		}

		var listofEventCategoriesMissing []string
		for k, v := range eventCateGoryMap {
			if !v {
				result.Status = Fail
				listofEventCategoriesMissing = append(listofEventCategoriesMissing, k)
				// printer.AddInstance(k, Fail, "only a subset of events under event category is present, others are missing for sns subscription")
				// result.FailReason = fmt.Errorf("only a subset of events under event category is present, event category subscription is missing  %s ", k)
				// return result
			}
		}

		ConvertSliceToString := func(arr []string) string {
			sort.Strings(arr)
			return strings.Join(arr, ", ")
		}

		if len(listofEventCategoriesMissing) > 0 {
			commaSeperatedString := ConvertSliceToString(listofEventCategoriesMissing)
			for _, srcID := range arrayOfSourceIDList {
				dbResult, ok := dbResultMap[srcID]
				if !ok {
					dbResult = model.NewCaseResult(srcID)
				}
				dbResult.Status = Fail
				dbResult.Reason = dbResult.Reason + ", only a subset of events under event category is present, others like " + commaSeperatedString + " are missing for sns subscriptions"
			}
			return
		}

	}

	// this is the case where it has failed for the case where two databases exist , we have one source ID list and we got all category events. So we failed the check
	// but sourceIDList for this passed so over all it is failure but for database1 it is pass
	if result.Status != Fail {
		result.Status = Pass
	}
	return
}

func GetSourceIDList(sub *EventSubscription) (sourceIDlist []string, sourceIDlistNil bool) {
	// if sub.SourceType != DBInstanceType {
	// 	sourceIDlistNil = true
	// 	return
	// }
	// source ID list is nil that means we have subscription for all
	if sub.SourceIdsList == nil {
		sourceIDlistNil = true
		return
	}

	// all the instances type are covered && all event category list are covered for all instances
	if sub.SourceIdsList != nil {
		var sourceIDStrs []string
		// type case sourceIDList to  array first
		sourceIDs, ok := sub.SourceIdsList.([]interface{})
		if !ok {
			// []string array are not apparerntly []interface{} so we need to give support for []string for test cases
			sourceIDStrs, ok = sub.SourceIdsList.([]string)
			if !ok {
				log.Println("sourceIDsList is not array", sub.SourceIdsList)
				return
			}
		}
		for _, srcID := range sourceIDs {
			strSourceID, ok := srcID.(string)
			if !ok {
				log.Println("can not convert sourceID to string", srcID)
				return
			}
			sourceIDlist = append(sourceIDlist, strSourceID)
		}
		sourceIDlist = append(sourceIDlist, sourceIDStrs...)
	}
	return
}

func GetEventCategoryList(sub *EventSubscription) (eventCategoryList []string, eventCategoryListNil bool) {
	// if sub.SourceType != DBSecurityGroup {
	// 	eventCategoryListNil = true
	// 	return
	// }
	// source ID list is nil that means we have subscription for all
	if sub.EventCategoriesList == nil {
		eventCategoryListNil = true
		return
	}

	// all the instances type are covered && all event category list are covered for all instances
	if sub.EventCategoriesList != nil {
		var eventIDStrs []string
		eventCategories, ok := sub.EventCategoriesList.([]interface{})
		if !ok {
			// []string array are not apparerntly []interface{} so we need to give support for []string for test cases
			eventIDStrs, ok = sub.EventCategoriesList.([]string)
			if !ok {
				log.Println("eventCategoryList is not array", sub.SourceIdsList)
				return
			}
		}
		for _, eventID := range eventCategories {
			strEventID, ok := eventID.(string)
			if !ok {
				log.Println("can not convert eventID to string", eventID)
				return
			}
			eventCategoryList = append(eventCategoryList, strEventID)
		}
		eventCategoryList = append(eventCategoryList, eventIDStrs...)
	}
	return
}
