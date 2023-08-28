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

const (
	EmptySubscriptions = `┌───────────┬────────┬─────────────────────────────────────┐
	│ Instance  │ Status │ Current Value                       │
	├───────────┼────────┼─────────────────────────────────────┤
	│ database2 │ Fail   │ no subscription found for database2 │
	├───────────┼────────┼─────────────────────────────────────┤
	│ database1 │ Fail   │ no subscription found for database1 │
	└───────────┴────────┴─────────────────────────────────────┘`
	NoSubscriptionsFound = "no subscription found for database1"
)

func TestExecute430(t *testing.T) {

	dbMap := make(map[string]bool)
	dbMap["database1"] = true
	dbMap["database2"] = true
	var msg *mock.MockSubscriptionGetter
	var db *mock.MockDBGetter
	ctrl := gomock.NewController(t)
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

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			return nil, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}

		if len(result.CaseFailReason) != len(dbMap) {
			t.Error("not all databases got failure reasons")
		}

		if result.CaseFailReason["database1"].Status != rds.Fail {
			t.Error("database doesn't have correct status")
		}

		if result.CaseFailReason["database1"].Reason != NoSubscriptionsFound {
			t.Error("database doesn't have correct failure reason")
		}
	})

	t.Run("rds event  subscriptions returns one record sourceIDlist is empty and no source type is there no event category is there", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()
		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status: "active",
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.FailReason)
		}
	})

	t.Run("rds event  subscriptions returns one record souceIDlist is emtpy and source type is db-instance type", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {

			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	// this case is not valid commenting it out
	// t.Run("rds event  subscriptions returns one record and source type is not db-instance", func(t *testing.T) {
	// 	setSubGetter()
	// 	db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
	// 		return nil, dbMap, nil
	// 	}).AnyTimes()

	// 	msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
	// 		var subs []rds.EventSubscription
	// 		subs = append(subs, rds.EventSubscription{
	// 			Status:     "active",
	// 			SourceType: "something",
	// 		})
	// 		return subs, nil
	// 	}).AnyTimes()
	// 	result := rds.Execute430(context.Background())
	// 	if result.Status != rds.Fail {
	// 		t.Error(result.Status)
	// 	}
	// })

	t.Run("rds event  subscriptions returns multiple records but one passes all the event source and category are enabled it should pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
			}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event  subscriptions returns multiple records but one passes which has only status active and no db instance type as well still all the event source and category are enabled it should pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status: "active",
			}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions returns  proper status and other has data with empty sourceIDlist and empty event category list we will return status as pass", func(t *testing.T) {
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
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event  subscriptions returns empty record then it is a pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event  subscriptions returns multiple records but one no proper status and other has data with empty sourceIDlist and empty event category list we will return status as pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
					"database3",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event  subscriptions returns data with empty sourceIDlist and empty event category list we will return status as pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				Status:     "Active",
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event  subscriptions returns multiple records but one no proper status and other has data with empty sourceIDlist and empty event category but status active is false list we will return status as pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions returns multiple records but one has few records and other has few records we will return status as manual", func(t *testing.T) {
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
				}}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database-3",
					"database-4",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Manual {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), rds.ManualCheckNeeded) {
			fmt.Println(result.FailReason)
			t.Error("expect manual check needed")
		}
	})

	t.Run("rds event subscriptions which has event category but every thing else empty ", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBSecurityGroup,
				SourceIdsList: []string{
					"database1",
					"database2",
				}}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBSecurityGroup,
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Manual {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions which has event category ", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBSecurityGroup,
				SourceIdsList: []string{
					"database1",
					"database2",
				}}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBSecurityGroup,
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Manual {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions which has event category type but some ID list ", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBSecurityGroup,
				SourceIdsList: []string{
					"database1",
					"database2",
				}})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	// not a valid test case
	// t.Run("rds event subscriptions which has event category then it is a pass", func(t *testing.T) {
	// 	setSubGetter()
	// 	db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
	// 		return nil, dbMap, nil
	// 	}).AnyTimes()

	// 	msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
	// 		var subs []rds.EventSubscription
	// 		subs = append(subs, rds.EventSubscription{
	// 			Status:     "active",
	// 			SourceType: rds.DBSecurityGroup})
	// 		return subs, nil
	// 	}).AnyTimes()
	// 	result := rds.Execute430(context.Background())
	// 	if result.Status != rds.Fail {
	// 		t.Error(result.Status)
	// 	}
	// })

	t.Run("rds event subscriptions which has event category then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute440(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions which has event subscription correct for ond database then it should pass for it and others should be fail", func(t *testing.T) {
		setSubGetter()
		dbSubMap := make(map[string]bool)
		dbSubMap["database1"] = true
		dbSubMap["database2"] = true
		dbSubMap["database3"] = true
		dbSubMap["database4"] = true

		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbSubMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
				}})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for database1") {
			fmt.Println(result.FailReason)
			t.Error("expect subscription found for database1")
		}
	})

	// {
	// 	"CustomerAwsId": "320240993546",
	// 	"CustSubscriptionId": "testunconfirmed",
	// 	"SnsTopicArn": "arn:aws:sns:us-west-1:320240993546:testemail",
	// 	"Status": "active",
	// 	"SubscriptionCreationTime": "2023-08-23 04:25:33.938",
	// 	"SourceType": "db-instance",
	// 	"SourceIdsList": [
	// 		"database-1"
	// 	],
	// 	"Enabled": true,
	// 	"EventSubscriptionArn": "arn:aws:rds:us-west-1:320240993546:es:testunconfirmed"
	// }

	t.Run("rds event subscriptions which has event category then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute440(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions which has event category then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType}, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBInstanceType})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute440(context.Background())
		if result.Status != rds.Manual {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions which has event category list then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:     "active",
				SourceType: rds.DBSecurityGroup,
				EventCategoriesList: []string{
					"change",
					"delete",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions has all databases and all event categories it is a pass", func(t *testing.T) {
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
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions has one out of two databases and all event categories it is a fail", func(t *testing.T) {
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
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions has two databases and one event categories  is missing it is a fail", func(t *testing.T) {
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
				EventCategoriesList: []string{
					"deletion",
					"failure",
					"low storage",
					"maintenance",
					"notification",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "only a subset of events under event category is present") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present")
		}
	})

	//	"EventSubscriptionsList": [
	//     {
	//         "CustomerAwsId": "320240993546",
	//         "CustSubscriptionId": "testsomeventsonallinstances",
	//         "SnsTopicArn": "arn:aws:sns:us-west-1:320240993546:testsomeventsonallinstances",
	//         "Status": "active",
	//         "SubscriptionCreationTime": "2023-08-23 23:48:30.473",
	//         "SourceType": "db-instance",
	//         "EventCategoriesList": [
	//             "availability",
	//             "low storage"
	//         ],
	//         "Enabled": true,
	//         "EventSubscriptionArn": "arn:aws:rds:us-west-1:320240993546:es:testsomeventsonallinstances"
	//     }
	// ]

	t.Run("rds event subscriptions has two databases and one event categories  is missing it is a fail", func(t *testing.T) {
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
				EventCategoriesList: []interface{}{
					"availability",
					"low storage",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "only a subset of events under event category is present") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present")
		}
	})

	// "EventSubscriptionsList": [
	//     {
	//         "CustomerAwsId": "320240993546",
	//         "CustSubscriptionId": "testsns2",
	//         "SnsTopicArn": "arn:aws:sns:us-west-1:320240993546:testsns1",
	//         "Status": "active",
	//         "SubscriptionCreationTime": "2023-08-28 03:38:16.131",
	//         "SourceType": "db-security-group",
	//         "Enabled": true,
	//         "EventSubscriptionArn": "arn:aws:rds:us-west-1:320240993546:es:testsns2"
	//     }
	// ]

	t.Run("rds event subscriptions has two databases and it is of type db-security group then it is a fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:               "active",
				SourceType:           rds.DBSecurityGroup,
				CustomerAwsID:        "320240993546",
				CustSubscriptionID:   "testsns2",
				SnsTopicArn:          "arn:aws:sns:us-west-1:320240993546:testsns1",
				Enabled:              true,
				EventSubscriptionArn: "arn:aws:rds:us-west-1:320240993546:es:testsns2",
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		// if !strings.Contains(result.FailReason.(string), "only a subset of events under event category is present") {
		// 	fmt.Println(result.FailReason)
		// 	t.Error("expect only a subset of events under event category is present")
		// }
	})

	// "EventSubscriptionsList": [
	//     {
	//         "CustomerAwsId": "320240993546",
	//         "CustSubscriptionId": "testsns42",
	//         "SnsTopicArn": "arn:aws:sns:us-west-1:320240993546:testsnstopic",
	//         "Status": "active",
	//         "SubscriptionCreationTime": "2023-08-24 00:45:20.95",
	//         "SourceType": "db-instance",
	//         "Enabled": true,
	//         "EventSubscriptionArn": "arn:aws:rds:us-west-1:320240993546:es:testsns42"
	//     }
	// ]

	t.Run("rds event subscriptions is only one with out mention of any thing then it should be pass", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				Status:      "active",
				SourceType:  rds.DBInstanceType,
				SnsTopicArn: "arn:aws:sns:us-west-1:320240993546:testsnstopic",
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for") {
			fmt.Println(result.FailReason)
			t.Error("expect subscription to be found")
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

	t.Run("rds event subscriptions is subset of subscriptions it should fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				EventCategoriesList: []interface{}{
					"availability",
					"low storage",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "only a subset of events under event category is present") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
	})

	// {
	//     "SourceType": "db-instance",
	//     "SourceIdsList": [
	//         "database-1",
	//         "database-2"
	//     ],
	//     "EventCategoriesList": [
	//         "availability",
	//         "creation"
	//     ]
	// }

	t.Run("rds event subscriptions is subset of subscriptions it should fail", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				EventCategoriesList: []interface{}{
					"availability",
					"low storage",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "only a subset of events under event category is present") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
	})

	t.Run("rds event subscriptions which 4 databases but we have subscriptions for only 2 and has event category also as subset should fail", func(t *testing.T) {
		setSubGetter()
		dbSubMap := make(map[string]bool)
		dbSubMap["database1"] = true
		dbSubMap["database2"] = true
		dbSubMap["database3"] = true
		dbSubMap["database4"] = true

		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbSubMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				EventCategoriesList: []interface{}{
					"availability",
					"low storage",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for database1, only a subset of events under event category is present, others like deletion, failover, failure, maintenance, notification are missing for sns subscriptions") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for database2, only a subset of events under event category is present, others like deletion, failover, failure, maintenance, notification are missing for sns subscriptions") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
		if !strings.Contains(result.FailReason.(string), "no subscription found for database3") {
			fmt.Println(result.FailReason)
			t.Error("should print for which it is not having subscription")
		}
		if !strings.Contains(result.FailReason.(string), "no subscription found for database4") {
			fmt.Println(result.FailReason)
			t.Error("should print for which it is not having subscription")
		}

	})

	t.Run("rds event subscriptions which 4 databases but we have subscriptions for all and has event category also as subset should fail", func(t *testing.T) {
		setSubGetter()
		dbSubMap := make(map[string]bool)
		dbSubMap["database1"] = true
		dbSubMap["database2"] = true
		dbSubMap["database3"] = true
		dbSubMap["database4"] = true

		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbSubMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				EventCategoriesList: []interface{}{
					"availability",
					"low storage",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Fail {
			t.Error(result.Status)
		}

		if !strings.Contains(result.FailReason.(string), "subscription found for database1, only a subset of events under event category is present, others like deletion, failover, failure, maintenance, notification are missing for sns subscriptions") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for database2, only a subset of events under event category is present, others like deletion, failover, failure, maintenance, notification are missing for sns subscriptions") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for database3, only a subset of events under event category is present, others like deletion, failover, failure, maintenance, notification are missing for sns subscriptions") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}
		if !strings.Contains(result.FailReason.(string), "subscription found for database4, only a subset of events under event category is present, others like deletion, failover, failure, maintenance, notification are missing for sns subscriptions") {
			fmt.Println(result.FailReason)
			t.Error("expect only a subset of events under event category is present to be found")
		}

	})

	t.Run("rds event subscriptions which 4 databases but we have subscriptions for all and has event category for all then pass", func(t *testing.T) {
		setSubGetter()
		dbSubMap := make(map[string]bool)
		dbSubMap["database1"] = true
		dbSubMap["database2"] = true
		dbSubMap["database3"] = true
		dbSubMap["database4"] = true

		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbSubMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
					"database3",
					"database4",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Pass {
			t.Error(result.Status)
		}
	})

	t.Run("rds event subscriptions is subset of subscriptions but multiple it should manual", func(t *testing.T) {
		setSubGetter()
		db.EXPECT().GetDBMap(gomock.Any()).DoAndReturn(func(ctx context.Context) (*model.Result, map[string]bool, error) {
			return nil, dbMap, nil
		}).AnyTimes()

		msg.EXPECT().GetEventSubscription(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]rds.EventSubscription, error) {
			var subs []rds.EventSubscription
			subs = append(subs, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				EventCategoriesList: []interface{}{
					"availability",
					"low storage",
				},
			}, rds.EventSubscription{
				SourceType: rds.DBInstanceType,
				SourceIdsList: []string{
					"database1",
					"database2",
				},
				EventCategoriesList: []interface{}{
					"mainteanance",
				},
			})
			return subs, nil
		}).AnyTimes()
		result := rds.Execute430(context.Background())
		if result.Status != rds.Manual {
			t.Error(result.Status)
		}
	})

}
