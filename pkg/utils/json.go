package utils

import (
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"strings"
)

func GetJSON(store *sql.DB, sqlString string) ([]map[string]interface{}, error) {
	stmt, err := store.Prepare(sqlString)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	tableData := make([]map[string]interface{}, 0)

	count := len(columns)
	values := make([]interface{}, count)
	scanArgs := make([]interface{}, count)
	for i := range values {
		scanArgs[i] = &values[i]
	}

	for rows.Next() {
		err := rows.Scan(scanArgs...)
		if err != nil {
			return nil, err
		}

		entry := make(map[string]interface{})
		for i, col := range columns {
			v := values[i]

			b, ok := v.([]byte)
			if ok {
				entry[col] = string(b)
			} else {
				entry[col] = v
			}
		}

		tableData = append(tableData, entry)
	}

	// jsonData, err := json.Marshal(tableData)
	// if err != nil {
	// 	return "", err
	// }

	// return string(jsonData), nil
	return tableData, nil
}

// function to check if file exists
func DoesFileExist(fileName string) bool {
	_, error := os.Stat(fileName)

	// check if error is "file not exists"
	return !os.IsNotExist(error)
}
func GetFailReasonInString(failReason interface{}) string {
	switch ty := failReason.(type) {

	case string:
		return failReason.(string)
	case []map[string]interface{}:
		result := ""
		for _, n := range ty {
			for key, value := range n {
				result += fmt.Sprintf("%s:%v, ", key, value)
			}
			result += "\n"

		}
		return result
	case []interface{}:
		result := ""
		for _, item := range ty {
			switch itemTy := item.(type) {
			case map[string]interface{}:
				for key, value := range itemTy {
					result += fmt.Sprintf("%s: %v, ", key, value)
				}
				result = strings.TrimSuffix(result, ", ") + "\n" // Clean up trailing comma and add newline
			default:
				result += fmt.Sprintf("Unsupported item type: %v\n", reflect.TypeOf(item))
			}
		}
		return result

	default:
		var r = reflect.TypeOf(failReason)
		return fmt.Sprintf("Other:%v\n", r)
	}

}
