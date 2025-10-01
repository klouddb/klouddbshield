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
			out.LogConnections = val["setting"] == "on" || val["setting"] == "yes"
		}
	}

	return out, nil
}

func GetLoglinePrefix(ctx context.Context, store *sql.DB) (string, error) {
	query := `SELECT name, setting FROM pg_settings WHERE name IN ('log_line_prefix');`
	data, err := GetJSON(store, query)
	if err != nil {
		return "", fmt.Errorf("error while getting pg_settings: %v", err)
	}

	for _, val := range data {
		if val["name"] == "log_line_prefix" {
			return fmt.Sprintf("%v", val["setting"]), nil
		}
	}

	return "", nil
}

func GetDataDirectory(ctx context.Context, store *sql.DB) (string, error) {
	query := `SHOW data_directory;`
	data, err := GetJSON(store, query)
	if err != nil {
		return "", fmt.Errorf("error while getting data_directory: %v", err)
	}

	for _, val := range data {
		if val["data_directory"] != nil {
			return fmt.Sprintf("%v", val["data_directory"]), nil
		}
	}

	return "", nil
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

func GetHBAFilePath(ctx context.Context, store *sql.DB) (string, error) {
	query := `SHOW hba_file;`
	data, err := GetJSON(store, query)
	if err != nil {
		return "", fmt.Errorf("error while getting hba_file: %v", err)
	}

	hbaFilePath := ""
	for _, val := range data {
		if val["hba_file"] != nil {
			hbaFilePath = fmt.Sprint(val["hba_file"])
			break
		}
	}

	return hbaFilePath, nil
}
