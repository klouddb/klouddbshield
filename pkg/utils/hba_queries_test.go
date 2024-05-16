package utils

import (
	"context"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/klouddb/klouddbshield/model"
)

func TestGetDatabaseAndHostForUSerFromHbaFileRules(t *testing.T) {

	tests := []struct {
		name        string
		QueryResult [][5]interface{}
		want        []model.HBAFIleRules
		wantErr     bool
	}{
		// TODO: Add test cases.
		{
			name: "all database and user with localhost",
			QueryResult: [][5]interface{}{
				{95, "{all}", "{all}", "127.0.0.1", "255.255.255.255"},
			},
			wantErr: false,
			want: []model.HBAFIleRules{
				{
					LineNumber: 95,
					Database:   "all",
					UserName:   "all",
					Address:    "127.0.0.1",
					NetMask:    "255.255.255.255",
				},
			},
		},
		{
			name: "all default entries from hba file rules",
			QueryResult: [][5]interface{}{
				{95, "{all}", "{all}", "127.0.0.1", "255.255.255.255"},
				{97, "{all}", "{all}", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
				{100, "{replication}", "{all}", "127.0.0.1", "255.255.255.255"},
				{102, "{replication}", "{all}", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
				{103, "{testing1}", "{pradip,testuser,newuser,pradipparmar}", ".example.com", nil},
			},
			wantErr: false,
			want: []model.HBAFIleRules{
				{
					LineNumber: 95,
					Database:   "all",
					UserName:   "all",
					Address:    "127.0.0.1",
					NetMask:    "255.255.255.255",
				},
				{
					LineNumber: 97,
					Database:   "all",
					UserName:   "all",
					Address:    "::1",
					NetMask:    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				},
				{
					LineNumber: 100,
					Database:   "replication",
					UserName:   "all",
					Address:    "127.0.0.1",
					NetMask:    "255.255.255.255",
				},
				{
					LineNumber: 102,
					Database:   "replication",
					UserName:   "all",
					Address:    "::1",
					NetMask:    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				},
				{
					LineNumber: 103,
					Database:   "testing1",
					UserName:   "pradip,testuser,newuser,pradipparmar",
					Address:    ".example.com",
					NetMask:    "",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create a mock SQL database
			mockDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create mock database: %v", err)
			}
			defer mockDB.Close()

			// Create the expected SQL query
			expectedQuery := "select line_number, database, user_name, address, netmask from pg_hba_file_rules where type != 'local';"

			// Set up the mock expectation for the query and result
			rows := sqlmock.NewRows([]string{"line_number", "database", "user_name", "address", "netmask"})
			for _, data := range tt.QueryResult {
				rows.AddRow(data[0], data[1], data[2], data[3], data[4])
			}

			mock.ExpectPrepare(expectedQuery).ExpectQuery().WillReturnRows(rows)

			got, err := GetDatabaseAndHostForUSerFromHbaFileRules(context.Background(), mockDB)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDatabaseAndHostForUSerFromHbaFileRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDatabaseAndHostForUSerFromHbaFileRules() = %v, want %v", got, tt.want)
			}
		})
	}
}
