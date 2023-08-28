package rds_test

import (
	"context"
	"testing"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/rds"
	"github.com/klouddb/klouddbshield/rds/mock"
	"go.uber.org/mock/gomock"
)

func TestExecute440(t *testing.T) {

	dbMap := make(map[string]bool)
	dbMap["database1"] = true
	dbMap["database2"] = true
	var msg *mock.MockSubscriptionGetter
	ctrl := gomock.NewController(t)
	db := mock.NewMockDBGetter(ctrl)
	rds.DataBaseGetter = db
	setSubGetter := func() {
		msg = mock.NewMockSubscriptionGetter(ctrl)
		db = mock.NewMockDBGetter(ctrl)
		rds.SubGetter = msg
		rds.DataBaseGetter = db
	}

	t.Run("no rds event  subscriptions at all", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) (*rds.RdsSubscriptions, error) {
			return nil, nil
		}).AnyTimes()

		result := rds.Execute440(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	// "EventSubscriptionsList": [
	//     {
	//         "CustomerAwsId": "320240993546",
	//         "CustSubscriptionId": "testeventcat",
	//         "SnsTopicArn": "arn:aws:sns:us-west-1:320240993546:testeventcat",
	//         "Status": "active",
	//         "SubscriptionCreationTime": "2023-08-24 14:03:51.767",
	//         "SourceType": "db-instance",
	//         "Enabled": true,
	//         "EventSubscriptionArn": "arn:aws:rds:us-west-1:320240993546:es:testeventcat"
	//     }
	// ]

	t.Run("rds event subscriptions event subscriptions and it is doesn't have any type but and status is active it is still pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:        "active",
				CustomerAwsID: "320240993546",
				SnsTopicArn:   "arn:aws:sns:us-west-1:320240993546:testeventcat",
			})
			return subs, nil
		}).AnyTimes()

		result := rds.Execute440(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions event subscriptions and it is doesn't have any type but and status is something it is still pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:        "Something",
				CustomerAwsID: "320240993546",
				SnsTopicArn:   "arn:aws:sns:us-west-1:320240993546:testeventcat",
			})

			return subs, nil
		}).AnyTimes()

		result := rds.Execute440(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions event subscriptions  it is of type db-instance then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:        "Something",
				CustomerAwsID: "320240993546",
				SnsTopicArn:   "arn:aws:sns:us-west-1:320240993546:testeventcat",
				SourceType:    "db-instance",
			})

			return subs, nil
		}).AnyTimes()

		result := rds.Execute440(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions event subscriptions and it is of tupe security grou pthen it is a pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {

			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:        "Something",
				CustomerAwsID: "320240993546",
				SnsTopicArn:   "arn:aws:sns:us-west-1:320240993546:testeventcat",
				SourceType:    "db-security-group",
			})

			return subs, nil
		}).AnyTimes()

		result := rds.Execute440(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	// "EventSubscriptionsList": [
	//     {
	//         "CustomerAwsId": "320240993546",
	//         "CustSubscriptionId": "testeventcat",
	//         "SnsTopicArn": "arn:aws:sns:us-west-1:320240993546:testeventcat",
	//         "Status": "active",
	//         "SubscriptionCreationTime": "2023-08-24 14:03:51.767",
	//         "SourceType": "db-instance",
	//         "EventCategoriesList": [
	//             "availability",
	//             "creation"
	//         ],
	//         "Enabled": true,
	//         "EventSubscriptionArn": "arn:aws:rds:us-west-1:320240993546:es:testeventcat"
	//     }
	// ]

	// 	[
	//     {
	//         "SourceType": "db-instance",
	//         "SourceIdsList": null,
	//         "EventCategoriesList": [
	//             "availability",
	//             "creation"
	//         ]
	//     }
	// ]
	t.Run("rds event subscriptions event subscriptions and it is of type db instance then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
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
			return subs, nil
		}).AnyTimes()

		result := rds.Execute440(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.FailReason)
		}
	})
}
