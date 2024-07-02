package utils

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/model"
)

func GetDatabaseAndHostForUSerFromHbaFileRules(ctx context.Context, store *sql.DB) ([]model.HBAFIleRules, error) {
	sqlStr := `select line_number, database, user_name, address, netmask from pg_hba_file_rules where type != 'local';`
	stmt, err := store.Prepare(sqlStr)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.HBAFIleRules

	for rows.Next() {
		var data model.HBAFIleRules
		var addr, netmask sql.NullString
		err := rows.Scan(&data.LineNumber, &data.Database, &data.UserName, &addr, &netmask)
		if err != nil {
			return nil, err
		}

		if addr.Valid {
			data.Address = addr.String
		}
		if netmask.Valid {
			data.NetMask = netmask.String
		}

		data.Raw = fmt.Sprintf("From DB: database=%s, user=%s, address=%s, netmask=%s", data.Database, data.UserName, data.Address, data.NetMask)

		data.Database = data.Database[1 : len(data.Database)-1]
		data.UserName = data.UserName[1 : len(data.UserName)-1]

		out = append(out, data)
	}

	return out, nil
}

func GetUserForGivenRole(ctx context.Context, store *sql.DB, role string) ([]string, error) {
	sqlStr := `SELECT rolname FROM pg_roles WHERE pg_has_role( '` + role + `', oid, 'member');`
	stmt, err := store.Prepare(sqlStr)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string

	for rows.Next() {
		var username string
		err := rows.Scan(&username)
		if err != nil {
			return nil, err
		}

		out = append(out, username)
	}

	return out, nil
}
