package utils

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

// GetPGSettings will give log_connections using query.
// query := `SELECT name, setting FROM pg_settings WHERE name IN ('log_connections');`
func GetPGSettings(ctx context.Context, store *sql.DB) (*model.PgSettings, error) {
	query := `SELECT name, setting FROM pg_settings WHERE name IN ('log_connections');`
	data, err := GetJSON(store, query)
	if err != nil {
		return nil, fmt.Errorf("error while getting pg_settings: %v", err)
	}

	// parsing data to pgSettings struct
	out := &model.PgSettings{}
	for _, val := range data {
		if val["name"] == "log_connections" {
			out.LogConnections = val["setting"] == "on"
		}
		// else if val["name"] == "log_line_prefix" {
		// 	out.LogLinePrefix = fmt.Sprintf("%v", val["setting"])
		// }
	}

	return out, nil
}

func GetPGUsers(ctx context.Context, store *sql.DB) ([]string, error) {
	query := `SELECT usename FROM pg_user;`
	data, err := GetJSON(store, query)
	if err != nil {
		return nil, fmt.Errorf("error while getting pg_user: %v", err)
	}
	// log.Println(data)
	listOfPGUsers := []string{}

	for _, obj := range data {
		if obj["usename"] != nil {
			listOfPGUsers = append(listOfPGUsers, fmt.Sprint(obj["usename"]))

		}
	}
	return listOfPGUsers, nil
}
