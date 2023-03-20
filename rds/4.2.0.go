package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/klouddb/klouddbshield/model"
)

type SnsRdsEvents struct {
	EventSubscriptionsList []struct {
		EventCategoriesList      []string `json:"EventCategoriesList"`
		Enabled                  bool     `json:"Enabled"`
		EventSubscriptionArn     string   `json:"EventSubscriptionArn"`
		Status                   string   `json:"Status"`
		SourceType               string   `json:"SourceType"`
		CustomerAwsID            string   `json:"CustomerAwsId"`
		SubscriptionCreationTime string   `json:"SubscriptionCreationTime"`
		CustSubscriptionID       string   `json:"CustSubscriptionId"`
		SnsTopicArn              string   `json:"SnsTopicArn"`
		SourceIdsList            []string `json:"SourceIdsList"`
	} `json:"EventSubscriptionsList"`
}
type SNSSubscriptions struct {
	Subscriptions []struct {
		SubscriptionArn string `json:"SubscriptionArn"`
		Owner           string `json:"Owner"`
		Protocol        string `json:"Protocol"`
		Endpoint        string `json:"Endpoint"`
		TopicArn        string `json:"TopicArn"`
	} `json:"Subscriptions"`
}

var dbMap map[string]bool
var timeToRunAWSCommand time.Duration

func init() {
	dbMap = make(map[string]bool)
}

func GetDBMap(ctx context.Context) (*model.Result, map[string]bool, error) {
	if len(dbMap) > 0 {
		return &model.Result{Status: Pass}, dbMap, nil
	}
	start := time.Now()

	result, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'")
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error executing command %s", err)
		return result, dbMap, err
	}

	var arrayOfDataBases []string
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDataBases)
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error un marshalling %s", err)
		return result, dbMap, err
	}

	for _, dbName := range arrayOfDataBases {
		dbMap[dbName] = false
	}

	// Code to measure
	timeToRunAWSCommand = time.Since(start)
	log.Printf("\nthe average time taken to run aws command is %f seconds. Depending on this the over all time for running checks would be impacted", timeToRunAWSCommand.Seconds())
	return result, dbMap, nil

}

// Execute420
func Execute420(ctx context.Context) (result *model.Result) {
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "4.2.0"
		result.Description = "Ensure SNS topic is created for RDS events"
		result = fixFailReason(result)
	}()

	result, dbSubMap, err := GetDBMap(ctx)
	if err != nil {
		return result
	}

	result, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-event-subscriptions")
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error executing command %s", err)
		return result
	}

	var arrayOfSnsRdsEvents SnsRdsEvents
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfSnsRdsEvents)
	if err != nil {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error un marshalling cmdOutput.StdOut: %s, error :%s", cmdOutput.StdOut, err)
		return
	}

	if len(arrayOfSnsRdsEvents.EventSubscriptionsList) == 0 {
		result.Status = Fail
		result.FailReason = fmt.Errorf("no event subscription list present for databases")
		return
	}

	for _, sub := range arrayOfSnsRdsEvents.EventSubscriptionsList {
		for _, dbName := range sub.SourceIdsList {
			_, ok := dbSubMap[dbName]
			if ok {
				dbSubMap[dbName] = true
			}
		}
	}

	// check if we got subscription for all databases or not
	for dbName, isSubscribed := range dbSubMap {
		if !isSubscribed {
			result.Status = Fail
			result.FailReason = fmt.Errorf("no subscription found for %s", dbName)
			return
		}
	}

	for _, sub := range arrayOfSnsRdsEvents.EventSubscriptionsList {

		// this step2 is not required
		// result, cmdOutput, err = ExecRdsCommand(ctx, fmt.Sprintf(`aws sns get-topic-attributes --topic-arn %s`, sub.SnsTopicArn))
		// if err != nil {
		// 	result.Status = Fail
		// 	result.FailReason = fmt.Errorf("error getting sns topic attributes %s", err)
		// 	return result
		// }

		// var arrayOfRecords []interface{}
		// err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfRecords)
		// if err != nil {
		// 	result.Status = Fail
		// 	result.FailReason = fmt.Errorf("error un marshalling %s", err)
		// 	return
		// }
		// if len(arrayOfRecords) == 0 {
		// 	result.Status = Fail
		// 	result.FailReason = fmt.Errorf("the len of the databases storage encrypted to verify is not correct")
		// 	return
		// }

		result, cmdOutput, err = ExecRdsCommand(ctx, fmt.Sprintf(`aws sns list-subscriptions-by-topic --topic-arn %s`, sub.SnsTopicArn))
		if err != nil {
			result.Status = Fail
			result.FailReason = fmt.Errorf("error executing command %s", err)
			return result
		}

		var arrayOfSNSSubscriptions SNSSubscriptions
		err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfSNSSubscriptions)
		if err != nil {
			result.Status = Fail
			result.FailReason = fmt.Errorf("error un marshalling %s", err)
			return
		}
		if len(arrayOfSNSSubscriptions.Subscriptions) == 0 {
			result.Status = Fail
			result.FailReason = fmt.Errorf("the len of the databases storage encrypted to verify is not correct")
			return
		}

		for _, snsSub := range arrayOfSNSSubscriptions.Subscriptions {
			if snsSub.SubscriptionArn == "PendingConfirmation" {
				result.Status = Fail
				result.FailReason = fmt.Errorf("the subscription for the arn %s is pending", sub.SnsTopicArn)
				return
			}
		}

	}
	result.Status = Pass
	return result

}
