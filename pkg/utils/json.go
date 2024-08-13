package utils

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/klouddb/klouddbshield/model"
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

func GetTableResponse(store *sql.DB, sqlString string) (*model.SimpleTable, error) {
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

	tableData := &model.SimpleTable{
		Columns: columns,
	}

	count := len(columns)

	for rows.Next() {
		values := make([]interface{}, count)
		scanArgs := make([]interface{}, count)
		for i := range values {
			scanArgs[i] = &values[i]
		}

		err := rows.Scan(scanArgs...)
		if err != nil {
			return nil, err
		}

		for i := range values {
			b, ok := values[i].([]byte)
			if ok {
				values[i] = string(b)
			}
		}

		tableData.Rows = append(tableData.Rows, values)
	}

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

	case nil:
		return ""

	default:
		var r = reflect.TypeOf(failReason)
		return fmt.Sprintf("Other:%v\n", r)
	}

}

// LoadJsonTemplate loads the check numbers from json file.
//
// It assumes that the json file will have array of objects and each object will have check_number key
// and value of check_number will be the check number
func LoadJsonTemplate(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	type Data struct {
		CheckNumber string `json:"number"`
	}

	fileData := []Data{}
	err = json.NewDecoder(f).Decode(&fileData)
	if err != nil {
		return nil, err
	}

	out := []string{}
	for _, item := range fileData {
		out = append(out, item.CheckNumber)
	}

	return out, nil
}

// LoadCSVTemplate loads the check numbers from csv file.
//
// It assumes that the second column from csv will be the check number
// and we don't have header in csv
func LoadCSVTemplate(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	// considering that second column from csv will be the check number
	// and we don't have header in csv
	out := []string{}
	for _, record := range records {
		if len(record) < 2 {
			fmt.Println("Invalid record found in csv", record)
			continue
		}

		out = append(out, record[1])
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("No valid check number found in csv")
	}

	return out, nil
}

func SchemaExists(store *sql.DB, schemaName string) (bool, error) {
	var schemaExists bool
	err := store.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)", schemaName).Scan(&schemaExists)
	if err != nil {
		return false, err
	}
	return schemaExists, nil
}

func TableRowCount(store *sql.DB, tableName string) (int, error) {
	var count int
	err := store.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, tableName)).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func GetListFromQuery(store *sql.DB, sqlString string) ([]string, error) {
	list := []string{}
	rows, err := store.Query(sqlString)
	if err != nil {
		return nil, fmt.Errorf("Error executing query: %v", err)
	}

	defer rows.Close()

	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("Error scanning row: %v", err)
		}

		if v == "" {
			continue
		}

		list = append(list, v)
	}

	return list, nil
}
