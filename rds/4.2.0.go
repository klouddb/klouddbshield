package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/klouddb/klouddbshield/model"
)

type RdsSubscriptions struct {
	EventSubscriptionsList []EventSubscription `json:"EventSubscriptionsList"`
}

type EventSubscription struct {
	EventCategoriesList      any    `json:"EventCategoriesList"`
	SourceIdsList            any    `json:"SourceIdsList"`
	Enabled                  bool   `json:"Enabled"`
	EventSubscriptionArn     string `json:"EventSubscriptionArn"`
	Status                   string `json:"Status"`
	SourceType               string `json:"SourceType"`
	CustomerAwsID            string `json:"CustomerAwsId"`
	SubscriptionCreationTime string `json:"SubscriptionCreationTime"`
	CustSubscriptionID       string `json:"CustSubscriptionId"`
	SnsTopicArn              string `json:"SnsTopicArn"`
}

type SNSSubscriptions struct {
	Subscriptions []SNSSubscription `json:"Subscriptions"`
}

type SNSSubscription struct {
	SubscriptionArn string `json:"SubscriptionArn"`
	Owner           string `json:"Owner"`
	Protocol        string `json:"Protocol"`
	Endpoint        string `json:"Endpoint"`
	TopicArn        string `json:"TopicArn"`
}

var dbMap map[string]bool
var timeToRunAWSCommand time.Duration

var (
	ErrEmptySNSSubscriptions = fmt.Errorf("no sns subscriptions present")
)

func init() {
	dbMap = make(map[string]bool)
}

var RDSSubGetter RDSSubscriptionGetter

type RDSSubscriptionGetter interface {
	GetEventSubscription(ctx context.Context) (*RdsSubscriptions, error)
	GetSNSSubscriptions(ctx context.Context, subToCheck *EventSubscription) (*SNSSubscriptions, error)
}

type SnsChecks struct {
}

func (s *SnsChecks) GetEventSubscription(ctx context.Context) (*RdsSubscriptions, error) {
	_, cmdOutput, err := ExecRdsCommand(ctx, "aws rds describe-event-subscriptions")
	if err != nil {
		return nil, fmt.Errorf("error executing command %s", err)
	}

	var arrayOfDescribeEventSubs RdsSubscriptions
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDescribeEventSubs)
	if err != nil {
		return nil, err
	}

	if len(arrayOfDescribeEventSubs.EventSubscriptionsList) == 0 {
		return nil, ErrEmptySubscriptions
	}
	return &arrayOfDescribeEventSubs, nil
}

func (s *SnsChecks) GetSNSSubscriptions(ctx context.Context, subToCheck *EventSubscription) (*SNSSubscriptions, error) {

	_, cmdOutput, err := ExecRdsCommand(ctx, fmt.Sprintf(`aws sns list-subscriptions-by-topic --topic-arn %s`, subToCheck.SnsTopicArn))
	if err != nil {
		return nil, fmt.Errorf("error executing command %s", err)
	}

	var arrayOfSNSSubscriptions SNSSubscriptions
	err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfSNSSubscriptions)
	if err != nil {
		return nil, err
	}

	if len(arrayOfSNSSubscriptions.Subscriptions) == 0 {
		return nil, ErrEmptySNSSubscriptions
	}
	return &arrayOfSNSSubscriptions, nil
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

func GetName(sub *EventSubscription) string {
	name := sub.SnsTopicArn
	if name == "" {
		name = sub.EventSubscriptionArn
	}
	if name == "" {
		name = sub.CustomerAwsID
	}
	if name == "" {
		name = sub.CustSubscriptionID
	}
	if name == "" {
		name = "SNS Topic"
	}
	return name
}

// Execute420 ...
func Execute420(ctx context.Context) (result *model.Result) {
	if result == nil {
		result = &model.Result{}
	}
	casResultMap := make(map[string]*model.CaseResult)
	result.CaseFailReason = casResultMap

	printer := NewRDSInstancePrinter()
	defer func() {
		if result == nil {
			result = &model.Result{}
		}
		result.Control = "4.2.0"
		result.Title = "Ensure SNS topic is created for RDS events"
		result = fixFailReason(result)
		isOneResultFail := false
		for snsName, caseResult := range casResultMap {
			if caseResult.Reason == Fail {
				isOneResultFail = true
			}
			printer.AddInstance(snsName, caseResult.Status, caseResult.Reason)
		}
		if len(casResultMap) > 0 {
			result.FailReason = printer.Print()
		}
		if result.Status != Fail && !isOneResultFail {
			result.Status = Pass
		}
	}()

	if RDSSubGetter == nil {
		RDSSubGetter = &SnsChecks{}
	}
	rdsSubscriptions, err := RDSSubGetter.GetEventSubscription(ctx)
	if err != nil || rdsSubscriptions == nil || len(rdsSubscriptions.EventSubscriptionsList) == 0 {
		result.Status = Fail
		result.FailReason = fmt.Errorf("error getting subscriptions %s", err)
		return
	}

	// we iterate all subscriptions to make sure snstopicArn is present for all. If not it is a failure
	for _, sub := range rdsSubscriptions.EventSubscriptionsList {
		name := GetName(&sub)
		casResultMap[name] = model.NewCaseResult(name)
		if sub.SnsTopicArn == "" {
			result.Status = Fail
			result.FailReason = fmt.Errorf("SnsTopicArn is empty")
			casResultMap[name].Status = Fail
			casResultMap[name].Reason = "SnsTopicArn is empty"
			continue
		}

		arrayOfSNSSubscriptions, err := RDSSubGetter.GetSNSSubscriptions(ctx, &sub)
		if err != nil {
			result.Status = Fail
			reason := fmt.Sprintf("error getting sns subscriptions %s", err)
			result.FailReason = reason
			casResultMap[name].Status = Fail
			casResultMap[name].Reason = reason
			continue
		}
		if arrayOfSNSSubscriptions == nil || len(arrayOfSNSSubscriptions.Subscriptions) == 0 {
			result.Status = Fail
			reason := "sns subscriptions empty"
			result.FailReason = reason
			casResultMap[name].Status = Fail
			casResultMap[name].Reason = reason
			continue
		}

		hasOnePending := false
		for _, snsSub := range arrayOfSNSSubscriptions.Subscriptions {
			if snsSub.SubscriptionArn == "PendingConfirmation" {
				result.Status = Fail
				reason := fmt.Sprintf("subscription for the arn %s has pending confirmation for %s", name, snsSub.Endpoint)
				result.FailReason = reason
				casResultMap[name].Status = Fail
				casResultMap[name].Reason = reason
				hasOnePending = true
				continue
			}
		}
		if !hasOnePending {
			reason := fmt.Sprintf("subscription for the arn %s is present", name)
			casResultMap[name].Status = Pass
			casResultMap[name].Reason = reason
		}
	}
	return result

}
