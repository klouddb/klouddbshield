package rds_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/rds"
	"github.com/klouddb/klouddbshield/rds/mock"
	"go.uber.org/mock/gomock"
)

func TestExecute420(t *testing.T) {

	dbMap := make(map[string]bool)
	dbMap["database1"] = true
	dbMap["database2"] = true
	var msg *mock.MockRDSSubscriptionGetter
	ctrl := gomock.NewController(t)
	db := mock.NewMockDBGetter(ctrl)
	rds.DataBaseGetter = db
	setSubGetter := func() {
		msg = mock.NewMockRDSSubscriptionGetter(ctrl)
		rds.RDSSubGetter = msg
	}

	t.Run("no rds event  subscriptions at all", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.RdsSubscriptions, error) {
			return nil, nil
		}).AnyTimes()

		msg.EXPECT().GetSNSSubscriptions(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.SNSSubscriptions, error) {
			return nil, nil
		}).AnyTimes()

		result := rds.Execute420(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions has sns subscriptions but snsTopicARN is empty then it is Fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.RdsSubscriptions, error) {
			rdsSubscriptions := &rds.RdsSubscriptions{}

			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"failover",
					"low storage",
					"maintenance",
					"notification",
				},
			})
			rdsSubscriptions.EventSubscriptionsList = append(rdsSubscriptions.EventSubscriptionsList, subs...)
			return rdsSubscriptions, nil
		}).AnyTimes()

		msg.EXPECT().GetSNSSubscriptions(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, subToCheck *rds.EventSubscription) (*rds.SNSSubscriptions, error) {
			snsSubscriptions := &rds.SNSSubscriptions{}
			snsSubscriptions.Subscriptions = append(snsSubscriptions.Subscriptions, rds.SNSSubscription{
				SubscriptionArn: "arn:aws:sns:us-west-1:932267803712:testinst:cb178db0-12f0-4a32-881a-b560dc3891cc",
				Owner:           "932267803712",
				Protocol:        "email",
				Endpoint:        "testdb@gmail.com",
				TopicArn:        "arn:aws:sns:us-west-1:932267803712:testinst",
			})

			return snsSubscriptions, nil
		}).AnyTimes()

		result := rds.Execute420(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "SnsTopicArn is empty") {
			fmt.Println(result.FailReason)
			t.Error("SnsTopicArn should be empty should come in error")
		}
	})

	t.Run("rds event subscriptions has sns subscriptions but snsTopicARN is not empty and we have confirmation then it is a pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.RdsSubscriptions, error) {
			rdsSubscriptions := &rds.RdsSubscriptions{}

			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				SnsTopicArn: "arn:aws:sns:us-west-1:932267803712:testinst",
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"failover",
					"low storage",
					"maintenance",
					"notification",
				},
			})
			rdsSubscriptions.EventSubscriptionsList = append(rdsSubscriptions.EventSubscriptionsList, subs...)
			return rdsSubscriptions, nil
		}).AnyTimes()

		msg.EXPECT().GetSNSSubscriptions(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, subToCheck *rds.EventSubscription) (*rds.SNSSubscriptions, error) {
			snsSubscriptions := &rds.SNSSubscriptions{}
			snsSubscriptions.Subscriptions = append(snsSubscriptions.Subscriptions, rds.SNSSubscription{
				SubscriptionArn: "arn:aws:sns:us-west-1:932267803712:testinst:cb178db0-12f0-4a32-881a-b560dc3891cc",
				Owner:           "932267803712",
				Protocol:        "email",
				Endpoint:        "testdb@gmail.com",
				TopicArn:        "arn:aws:sns:us-west-1:932267803712:testinst",
			})

			return snsSubscriptions, nil
		}).AnyTimes()

		result := rds.Execute420(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.FailReason)
		}
	})

	t.Run("rds has multiple event subscriptions has for each it returns sns subscriptions but snsTopicARN is not empty and we have confirmation once and no confirmation for others then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.RdsSubscriptions, error) {
			rdsSubscriptions := &rds.RdsSubscriptions{}

			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				SnsTopicArn: "arn:aws:sns:us-west-1:932267803712:testinst",
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"failover",
					"low storage",
					"maintenance",
					"notification",
				},
			}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				SnsTopicArn: "arn:aws:sns:us-west-1:932267803712:testinst",
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"failover",
					"low storage",
					"maintenance",
					"notification",
				},
			})
			rdsSubscriptions.EventSubscriptionsList = append(rdsSubscriptions.EventSubscriptionsList, subs...)
			return rdsSubscriptions, nil
		}).AnyTimes()

		count := 0
		msg.EXPECT().GetSNSSubscriptions(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, subToCheck *rds.EventSubscription) (*rds.SNSSubscriptions, error) {
			defer func() {
				count++
			}()
			snsSubscriptions := &rds.SNSSubscriptions{}
			if count == 0 {
				snsSubscriptions.Subscriptions = append(snsSubscriptions.Subscriptions, rds.SNSSubscription{
					SubscriptionArn: "arn:aws:sns:us-west-1:932267803712:testinst:cb178db0-12f0-4a32-881a-b560dc3891cc",
					Owner:           "932267803712",
					Protocol:        "email",
					Endpoint:        "testdb@gmail.com",
					TopicArn:        "arn:aws:sns:us-west-1:932267803712:testinst",
				})
			} else {
				snsSubscriptions.Subscriptions = append(snsSubscriptions.Subscriptions, rds.SNSSubscription{
					SubscriptionArn: "PendingConfirmation",
					Owner:           "932267803712",
					Protocol:        "email",
					Endpoint:        "testdb@gmail.com",
					TopicArn:        "arn:aws:sns:us-west-1:932267803712:testinst",
				})
			}

			return snsSubscriptions, nil
		}).AnyTimes()

		result := rds.Execute420(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.FailReason)
		}
		if !strings.Contains(result.FailReason.(string), "has pending confirmation for testdb@gmail.com") {
			fmt.Println(result.FailReason)
			t.Error("SnsTopicArn should show pending confirmation")
		}
	})

	t.Run("rds has multiple event subscriptions has for each it returns sns subscriptions but snsTopicARN is not empty and we have confirmation once and no confirmation for others then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.RdsSubscriptions, error) {
			rdsSubscriptions := &rds.RdsSubscriptions{}

			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				SnsTopicArn: "arn:aws:sns:us-west-1:932267803712:testinst",
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"failover",
					"low storage",
					"maintenance",
					"notification",
				},
			}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				SnsTopicArn: "arn:aws:sns:us-west-1:932267803712:testinst2",
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"failover",
					"low storage",
					"maintenance",
					"notification",
				},
			})
			rdsSubscriptions.EventSubscriptionsList = append(rdsSubscriptions.EventSubscriptionsList, subs...)
			return rdsSubscriptions, nil
		}).AnyTimes()

		msg.EXPECT().GetSNSSubscriptions(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, subToCheck *rds.EventSubscription) (*rds.SNSSubscriptions, error) {

			snsSubscriptions := &rds.SNSSubscriptions{}

			snsSubscriptions.Subscriptions = append(snsSubscriptions.Subscriptions, rds.SNSSubscription{
				SubscriptionArn: "arn:aws:sns:us-west-1:932267803712:testinst:cb178db0-12f0-4a32-881a-b560dc3891cc",
				Owner:           "932267803712",
				Protocol:        "email",
				Endpoint:        "testdb@gmail.com",
				TopicArn:        "arn:aws:sns:us-west-1:932267803712:testinst"})

			return snsSubscriptions, nil
		}).AnyTimes()

		result := rds.Execute420(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.FailReason)
		}
		if !strings.Contains(result.FailReason.(string), "is present") {
			fmt.Println(result.FailReason)
			t.Error("SnsTopicArn should show pending confirmation")
		}
	})

}
