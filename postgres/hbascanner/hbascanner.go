package hbascanner

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"

	// "github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

func HBAScannerByControl(store *sql.DB, ctx context.Context, control string) *model.HBAScannerResult {
	funcStore := map[int]func([]string, []int) *model.HBAScannerResult{
		1: CheckTrustInMethod,
		2: CheckAllInDatabase,
		3: CheckAllInUser,
		4: CheckMD5InMethod,
		5: CheckPeerInMethod,
		6: CheckIdentInMethod,
		7: CheckPasswordInMethod,
		8: CheckType,
		9: CheckIPPrivilege,
	}
	con, err := strconv.Atoi(control)
	if err != nil {
		// ... handle error
		fmt.Println("Invalid Control, Try Again!")
		os.Exit(1)
	}

	listRows, listOfLineNums, _ := GetHBAFileData(store, ctx)
	if _, ok := funcStore[con]; !ok {
		// the key 'elliot' exists within the map
		fmt.Println("Invalid Control, Try Again!")
		os.Exit(1)
	}

	result := funcStore[con](listRows, listOfLineNums)
	PrintVerbose(result)
	return result
}
func HBAScanner(store *sql.DB, ctx context.Context) []*model.HBAScannerResult {

	hbaqueryfuncStore := map[int]func(*sql.DB, context.Context) (*model.HBAScannerResult, error){
		1: QueryTrustInMethod,
		2: QueryAllInDatabase,
		3: QueryAllInUser,
		4: QueryMD5InMethod,
		5: QueryPeerInMethod,
		6: QueryIdentInMethod,
		7: QueryPasswordInMethod,
		8: QueryType,
		9: QueryIPPrivilege,
	}

	hbafilefuncStore := map[int]func([]string, []int) *model.HBAScannerResult{
		1: CheckTrustInMethod,
		2: CheckAllInDatabase,
		3: CheckAllInUser,
		4: CheckMD5InMethod,
		5: CheckPeerInMethod,
		6: CheckIdentInMethod,
		7: CheckPasswordInMethod,
		8: CheckType,
		9: CheckIPPrivilege,
	}
	var listOfResult []*model.HBAScannerResult
	runHBAFileCheck := false
	for i := 1; i <= len(hbaqueryfuncStore); i++ {
		result, err := hbaqueryfuncStore[i](store, ctx)
		if result == nil || err != nil {
			//	log.Println(err, i)

			runHBAFileCheck = true
			break
		}

		listOfResult = append(listOfResult, result)
	}
	if runHBAFileCheck {
		fmt.Println("Query check failed, trying via HBA file scanning")
		listOfResult = nil
		listRows, listOfLineNums, err := GetHBAFileData(store, ctx)
		if err != nil {
			fmt.Println("Got error while parsing HBA file", err)
			os.Exit(1)
		}
		for i := 1; i <= len(hbafilefuncStore); i++ {
			result := hbafilefuncStore[i](listRows, listOfLineNums)
			if result == nil {
				continue
			}
			listOfResult = append(listOfResult, result)
		}
	}

	return listOfResult
}
func PrintVerbose(result *model.HBAScannerResult) {

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	// hba check 1 - Check Trust In Method" - FAIL

	if result.Status == "Pass" {

		t.AppendSeparator()
		color := text.FgGreen
		// row := fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description)
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})

	} else {
		t.AppendSeparator()
		color := text.FgHiRed
		// row := fmt.Sprintf("HBA Check %d - %s", result.Control, result.Description)
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})
		t.AppendSeparator()
		t.AppendSeparator()

		t.AppendRow(table.Row{"Failed Rows", result.FailRowsInString})

	}
	t.AppendSeparator()
	t.AppendRow(table.Row{"Control", result.Control})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Description", result.Description})
	t.AppendSeparator()

	t.SetStyle(table.StyleLight)
	t.Render()

}

func GetHBAFileData(store *sql.DB, ctx context.Context) ([]string, []int, error) {

	result := []string{}
	query := `show hba_file;`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, nil, err
	}
	listOflineNum := []int{}
	hbaFile := ""
	for _, obj := range data {
		if obj["hba_file"] != nil {
			hbaFile = fmt.Sprint(obj["hba_file"])
			break
		}
	}
	fmt.Println("Found HBA conf file: " + hbaFile)
	f, err := os.OpenFile(hbaFile, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, nil, err
	}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text() // GET the line string
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		//	fmt.Println("----------------------------------------------------------------")
		// fmt.Println(line)
		result = append(result, line)
		listOflineNum = append(listOflineNum, lineNo)
		// listOfRow := strings.Fields(line)

		// fmt.Println(listOfRow, len(listOfRow))
		// fmt.Println("----------------------------------------------------------------")

	}

	return result, listOflineNum, nil
}
func CheckTrustInMethod(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Title:       "Check if Trust auth method is being used ",
		Description: "Usage of Trust method is not secure",
		Control:     1,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where
		auth_method='trust' or auth_method='TRUST';
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘trust’
		under auth-method`,
	}
	failedRows := []string{}
	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		size := len(listOfRow)
		method := listOfRow[size-1]
		if strings.EqualFold(method, "trust") {
			//						failedRows = append(failedRows, row)

			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckAllInDatabase(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Description: "Follow the least privilege method - Be specific and give the needed database(s) and not all",
		Control:     2,
		Title:       "Check if ‘all’ is used under database field ",
		Procedure: `
		Method 1 -
		select count(*) from pg_hba_file_rules where
		database='all';
		If the count is greater than 0 this is a FAIL
		Method 2 -
		Manually check your hba file to see if it contains ‘all’
		under database`,
	}
	failedRows := []string{}
	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		// size := len(listOfRow)
		database := listOfRow[1]
		if strings.EqualFold(database, "all") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckAllInUser(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Description: "Follow the least privilege method - Be specific and give the needed user(s) and not all",
		Control:     3,
		Title:       "Check if ‘all’ is used under user column",
		Procedure: `
		Method 1 -
		select count(*) from pg_hba_file_rules where
		user='all';
		If the count is greater than 0 this is a FAIL
		Method 2 -
		Manually check your hba file to see if it contains ‘all’
		under user`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		// size := len(listOfRow)
		user := listOfRow[2]
		if strings.EqualFold(user, "all") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckMD5InMethod(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Title:       "Check if md5 auth method is being used",
		Description: "Better to use scram-sha-256",
		Control:     4,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where
		auth_method='md5';
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘md5’
		under auth-method`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		size := len(listOfRow)
		method := listOfRow[size-1]
		if strings.EqualFold(method, "md5") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckPeerInMethod(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Title:       "Check if peer auth method is being used ",
		Description: "Review the lines in hba containing peer method.\nAlthough peer method might be ok to use, \nplease check the users and the hba lines to review furthe",
		Control:     5,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where
		auth_method='peer';
		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘md5’
		under auth-method`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		size := len(listOfRow)
		method := listOfRow[size-1]
		if strings.EqualFold(method, "peer") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckIdentInMethod(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Title:       "Check if ident auth method is being used ",
		Description: "Usage of Trust method is might not be secure",
		Control:     6,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where auth_method='ident';

		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘ident’ under auth-method
		`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		size := len(listOfRow)
		method := listOfRow[size-1]
		if strings.EqualFold(method, "ident") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckPasswordInMethod(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Description: "Usage of password method is might not be secure",
		Control:     7,
		Title:       "Check if password auth method is being used ",
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where auth_method='password';

		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘password’ under auth-method
		`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		size := len(listOfRow)
		method := listOfRow[size-1]
		if strings.EqualFold(method, "password") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckType(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Description: "Better to enforce ssl to secure your connections - use hostssl instead of host (after enabling ssl)",
		Title:       "Check for the presence of host under TYPE column (hostssl should be used for SSL)",
		Control:     8,
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where type='host';

		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains ‘host’ under type field
		`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		// size := len(listOfRow)
		dbtype := listOfRow[0]
		if !strings.EqualFold(dbtype, "host") {
			failedRows = append(failedRows, row)

			failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	return &result
}
func CheckIPPrivilege(listOfHBA []string, listOfLineNums []int) *model.HBAScannerResult {
	result := model.HBAScannerResult{
		Description: "Follow the least privilege method - Be specific and give the needed ip(s) and not all",
		Control:     9,
		Title:       "0.0.0.0/0 (IPv4) and ::0/0 (IPv6) in address field",
		Procedure: `
		Method 1-
		select count(*) from pg_hba_file_rules where address IN('0.0.0.0/0','::0/0');

		If the count is greater than 0 this is a FAIL
		Method 2-
		Manually check your hba file to see if it contains 0.0.0.0/0 (IPv4) and ::0/0 (IPv6) in address field
		`,
	}
	failedRows := []string{}

	failedRowLineNums := []int{}
	for key, row := range listOfHBA {
		listOfRow := strings.Fields(row)
		// size := len(listOfRow)
		dbtype := listOfRow[0]
		if strings.Contains(dbtype, "host") || strings.Contains(dbtype, "HOST") {
			if strings.Contains(listOfRow[3], "0.0.0.0/0") || strings.Contains(listOfRow[3], "::0/0") {
				failedRows = append(failedRows, row)
				failedRowLineNums = append(failedRowLineNums, listOfLineNums[key])
			}
		}
	}
	if len(failedRows) == 0 {
		result.Status = "Pass"
	} else {
		result.Status = "Fail"
		result.FailRows = failedRows
		result.FailRowsLineNums = failedRowLineNums
		result.FailRowsInString = strings.Join(failedRows, "\n")
	}
	fmt.Println(result.Status)
	return &result
}
