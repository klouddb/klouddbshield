package piiscanner

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/schollz/progressbar/v3"
)

var yesToAll bool

type Config struct {
	runOption    RunOption
	useSpacy     bool
	excludeTable utils.Set[string]
	includeTable []string

	Database string
	Schema   string

	printAllResults  bool
	spacyOnly        bool
	PrintSummaryOnly bool
}

func NewConfig(pgConfig *postgresdb.Postgres, runOption, excludeTable, includeTable, database, schema string,
	printAllResults, spacyOnly, printSummaryOnly bool) (*Config, error) {
	if printAllResults && printSummaryOnly {
		return nil, fmt.Errorf("--print-all and --print-summary are not allowed together")
	}

	if pgConfig == nil {
		return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}

	var useSpacy bool
	if runOption == RunOption_SpacyScan_String {
		useSpacy = true
		runOption = RunOption_DataScan_String
		printAllResults = true
	}

	if spacyOnly {
		// incase of spacy only we will run data scan only and that also with spacy
		// so if there run option is available then it will create confusion for users
		// that which part is getting priority from run option and spacy only.
		// so in that case we will return error
		if runOption != "" {
			return nil, fmt.Errorf("run option is not allowed with spacy only")
		}

		runOption = RunOption_DataScan_String
		useSpacy = true

		// incase of only spacy we will get all results with 0.3 confidence value
		// default terminal output prints only results with High confidence value which is > 0.7
		// so in case of spacy only we will print all results
		printAllResults = true
	}

	r, ok := RunOptionMap[runOption]
	if !ok {
		return nil, fmt.Errorf("invalid run option %s, valid options are %s", runOption, strings.Join(RunOptionSlice(), ", "))
	}

	if database == "" {
		database = pgConfig.DBName
	}

	out := &Config{
		runOption:        r,
		useSpacy:         useSpacy,
		Database:         database,
		Schema:           schema,
		printAllResults:  printAllResults,
		spacyOnly:        spacyOnly,
		PrintSummaryOnly: printSummaryOnly,
	}

	if excludeTable != "" {
		out.excludeTable = utils.NewSetFromSlice(utils.TrimSpaceArray(strings.Split(excludeTable, ",")))
	}

	if includeTable != "" {
		out.includeTable = utils.TrimSpaceArray(strings.Split(includeTable, ","))
	}

	return out, nil
}

type DBHelper interface {
	GetAllTables(ctx context.Context, store *sql.DB) ([]string, error)
	UpdateTableName(table string) string
}

type postgresDBHelper struct {
	schema string
}

func NewPostgresDBHelper(schema string) DBHelper {
	if schema == "" {
		schema = "public"
	}
	return &postgresDBHelper{schema: schema}
}

func (p *postgresDBHelper) GetAllTables(ctx context.Context, store *sql.DB) ([]string, error) {
	// check if schema exists
	exists, err := utils.SchemaExists(store, p.schema)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("schema %s does not exist", p.schema)
	}

	return utils.GetListFromQuery(store, "SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema = '"+p.schema+"'")
}

func (p *postgresDBHelper) UpdateTableName(table string) string {
	return fmt.Sprintf("\"%s\".\"%s\"", p.schema, table)
}

type databasePiiScanner struct {
	h                DBHelper
	store            *sql.DB
	tableScanManager *TableScanManager

	numOfRunners int

	cnf *Config
}

func NewDatabasePiiScanner(h DBHelper, store *sql.DB, cnf *Config) *databasePiiScanner {
	return &databasePiiScanner{
		h: h, store: store,
		numOfRunners: runtime.NumCPU(),
		cnf:          cnf,
	}
}

func (d *databasePiiScanner) WithNumOfRunners(n int) *databasePiiScanner {
	d.numOfRunners = n
	return d
}

func (d *databasePiiScanner) DetectorFactory() []Detector {
	detectors := []Detector{}

	if !d.cnf.spacyOnly {
		detectors = append(detectors, NewRegexValueDetector())
	}

	if d.cnf.useSpacy {
		detectors = append(detectors, NewSpacyDetector().WithWorkDirs([]string{"python", "/etc/klouddbshield/python", "../../python"}))
	}

	return detectors
}

func (d *databasePiiScanner) GetTables(ctx context.Context) ([]string, error) {
	if len(d.cnf.includeTable) != 0 {
		return d.cnf.includeTable, nil
	}

	tables, err := d.h.GetAllTables(ctx, d.store)
	if err != nil {
		return nil, fmt.Errorf("error getting tables: %v", err)
	}

	return tables, nil
}

func (d *databasePiiScanner) Scan(ctx context.Context) error {

	if d.cnf.runOption == RunOption_DeepScan {
		fmt.Println(text.FgCyan.Sprint("Scanning all rows may take a considerable amount of time. To speed up"))
		fmt.Println(text.FgCyan.Sprint("the process, consider using the 'datascan' option, which will scan only"))
		fmt.Println(text.FgCyan.Sprint("10,000 rows per table"))
		fmt.Println()
	}

	tables, err := d.GetTables(ctx)
	if err != nil {
		return err
	}

	if len(tables) == 0 {
		fmt.Println("> No tables found in database")
		return nil
	}

	fmt.Println("> Found", len(tables), "tables.")

	d.tableScanManager = NewTableScanManager().WithColumnDetector(NewRegexColumnDetector())
	if d.cnf.runOption != RunOption_MetaScan {
		d.tableScanManager.WithDetectorFactory(d.DetectorFactory)
	}

	initFunction := sync.OnceValue(func() error {
		err := d.tableScanManager.Start(ctx, d.numOfRunners)
		if err != nil {
			return err
		}

		fmt.Println("> Started table scan manager with", d.numOfRunners, "runners.")
		return nil
	})

	for _, table := range tables {
		if d.cnf.excludeTable != nil && d.cnf.excludeTable.Contains(table) {
			continue
		}

		err := initFunction()
		if err != nil {
			return fmt.Errorf("error starting table scan manager: %v", err)
		}

		// fmt.Println("> Processing table", table)
		s := NewPiiTableScanner(d.h.UpdateTableName(table), d.store, d.tableScanManager, d.cnf.runOption, d.cnf.useSpacy)
		if err := s.processTable(ctx); err != nil {
			return fmt.Errorf("error processing table %s: %v", table, err)
		}
		// fmt.Println("> Done processing table", table)
	}
	return nil
}

type DatabasePIIScanOutput struct {
	ScanType        string
	SupportedLevels []string
	Data            map[string]TableDetailOutput
}
type TableDetailOutput map[string][]PIIDataWithWeightString

type PIIDataWithWeightString struct {
	Label            PIILabel
	Confidence       string
	ConfidenceIcon   string
	Weight           float64
	DetectorType     DetectorType
	DetectorName     string
	ScanedValueCount int
	MatchedCount     int
}

func NewPIIDataWithWeightString(label PIILabel, Weight float64, detectorType DetectorType, detectorName string) *PIIDataWithWeightString {
	confidence, icon := getConfidenceLabel(Weight)
	return &PIIDataWithWeightString{
		Label:          label,
		Confidence:     confidence,
		ConfidenceIcon: icon,
		Weight:         Weight,
		DetectorType:   detectorType,
		DetectorName:   detectorName,
	}
}

func (p *PIIDataWithWeightString) SetScanedValueAndMatchCount(matchCount, scanedValueCount int) {
	p.ScanedValueCount = scanedValueCount
	p.MatchedCount = matchCount
}

func (d *databasePiiScanner) GetResults() (*DatabasePIIScanOutput, error) {
	if d.tableScanManager == nil {
		// this handles the case when no table is scanned
		return nil, nil
	}

	data, err := d.tableScanManager.Output()
	if err != nil {
		return nil, err
	}

	scanType := RunOptionTitleMap[d.cnf.runOption]
	if d.cnf.useSpacy {
		scanType = RunOption_SpacyScan_Title
	}

	output := &DatabasePIIScanOutput{
		ScanType:        scanType,
		SupportedLevels: []string{"High", "Medium", "Low"},
		Data:            make(map[string]TableDetailOutput),
	}

	for _, table := range data {
		output.Data[table.TableName] = make(map[string][]PIIDataWithWeightString)
		for columnName, piiMap := range table.PiiDataMap {
			output.Data[table.TableName][columnName] = []PIIDataWithWeightString{}

			for detector, piiData := range piiMap.ColumnMap {
				for label, pii := range piiData {
					piiDataWithWeight := NewPIIDataWithWeightString(label, pii.Weight, DetectorType_ColumnDetector, detector)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			count := d.tableScanManager.valueCount[table.TableName][columnName]
			for detector, piiData := range piiMap.ValueMap {
				for label, pii := range piiData {
					// fmt.Println("label", label, "pii", pii, "column", columnName, "count", count)
					var finalWeight float64
					if count != 0 {
						finalWeight = pii.Weight / float64(count) // 3 / 10 = 0.3
					}

					if PiiEntitiesForWeightMergeLogic.Contains(label) {
						// get column weight for the same label
						if finalWeight > piiMap.ColumnMap["regex"][label].Weight {
							finalWeight = (piiMap.ColumnMap["regex"][label].Weight + finalWeight) / 2 // (0.5 + 0.3) / 2 = 0.4
						}
					}

					piiDataWithWeight := NewPIIDataWithWeightString(label, finalWeight, DetectorType_ValueDetector, detector)
					piiDataWithWeight.SetScanedValueAndMatchCount(pii.Count, count)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			sort.Slice(output.Data[table.TableName][columnName], func(i, j int) bool {

				return OrderMap[string(output.Data[table.TableName][columnName][i].DetectorType)] >
					OrderMap[string(output.Data[table.TableName][columnName][j].DetectorType)] ||

					OrderMap[output.Data[table.TableName][columnName][i].DetectorName] >
						OrderMap[output.Data[table.TableName][columnName][j].DetectorName] ||

					output.Data[table.TableName][columnName][i].Weight > output.Data[table.TableName][columnName][j].Weight
			})

		}
	}

	// print output to console
	// this code is for testing just to validate the output we are storing here.
	// for table, columnData := range output.Data {
	// 	fmt.Println("Table:", table)
	// 	for column, piiData := range columnData {
	// 		fmt.Println("Column:", column)
	// 		for _, pii := range piiData {
	// 			fmt.Println("Label:", pii.Label, "Confidence:", pii.Confidence, "Weight:", pii.Weight, "DetectorType:", pii.DetectorType, "DetectorName:", pii.DetectorName, "ScanedValueCount:", pii.ScanedValueCount, "MatchedCount:", pii.MatchedCount)
	// 		}
	// 	}
	// }

	return output, nil
}

func getConfidenceLabel(weight float64) (string, string) {
	if weight < 0.4 {
		return "Low", "🔵"
	} else if weight < 0.7 {
		return "Medium", "🟡"
	} else {
		return "High", "🔴"
	}
}

type piiTableScanner struct {
	tableName string
	store     *sql.DB

	tableScanManager *TableScanManager

	runOption RunOption

	runSpacy bool
}

func NewPiiTableScanner(tableName string, store *sql.DB, tableScanManager *TableScanManager, runOption RunOption, runSpacy bool) *piiTableScanner {
	return &piiTableScanner{
		tableName: tableName,
		store:     store,
		// catcher:   catcher,
		tableScanManager: tableScanManager,

		runOption: runOption,
		runSpacy:  runSpacy,
	}
}

func (p *piiTableScanner) processTable(ctx context.Context) error {

	// defer fmt.Println("> Done processing table 1", p.tableName)
	columns, err := p.processColumns(ctx)
	if err != nil {
		return fmt.Errorf("error processing columns: %v", err)
	}

	if len(columns) == 0 {
		return nil
	}

	if p.runOption == RunOption_MetaScan {
		return nil
	}

	coloredTableName := text.Bold.Sprint(p.tableName)

	var bar *progressbar.ProgressBar
	var barchan chan struct{}
	if p.runOption == RunOption_DeepScan || p.runOption == RunOption_SpacyScan {
		rowCount, err := utils.TableRowCount(p.store, p.tableName)
		if err != nil {
			return fmt.Errorf("error getting row count for table %s: %v", p.tableName, err)
		}
		if rowCount == 0 {
			return nil
		}

		if !yesToAll && rowCount > DEEPSCAN_WARNINING_LIMIT && p.runOption == RunOption_DeepScan {
			fmt.Print("> ", coloredTableName, " has ", rowCount, " rows. Do you want to continue? (yes=Y | no=N | yes to all=A) : ")
			var input string
			fmt.Scanln(&input) //nolint:errcheck
			if strings.ToLower(input) == "n" {
				return nil
			} else if strings.ToLower(input) == "a" {
				yesToAll = true
			} else if strings.ToLower(input) != "y" {
				return fmt.Errorf("invalid input")
			}
		}
		if (p.runSpacy && rowCount > DEEPSCAN_SPACY_WARNING_LIMIT) || rowCount > DEEPSCAN_WARNINING_LIMIT {
			bar = progressbar.NewOptions(rowCount,
				progressbar.OptionSetDescription("Processing "+p.tableName+" table"),
				progressbar.OptionShowCount(),
				progressbar.OptionFullWidth(),
				progressbar.OptionSetItsString("rows"),
				progressbar.OptionShowIts(),
			)

			barchan = make(chan struct{})
			closeChan := make(chan struct{})
			go func() {
				count := 0
				t := time.NewTicker(time.Second)
				for {
					select {
					case <-barchan:
						count++
					case <-t.C:
						bar.Add(count) // nolint:errcheck
						count = 0
					case <-closeChan:
						bar.Finish() //nolint:errcheck
						fmt.Println()
						close(closeChan)
						close(barchan)
						t.Stop()
						// fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed"))
						return
					}
				}
			}()

			// this is to refresh progress bar every second if file is taking more then second to process
			defer func() {
				closeChan <- struct{}{}
			}()
		}
	}

	query := fmt.Sprintf(`SELECT "%s" FROM %s`, strings.Join(columns, `","`), p.tableName)
	if p.runOption == RunOption_DataScan {
		query = fmt.Sprintf(`SELECT "%s" FROM %s TABLESAMPLE BERNOULLI (10) LIMIT 10000`, strings.Join(columns, `","`), p.tableName)
	}

	// defer fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 1"))
	stmt, err := p.store.Prepare(query)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v query:(%s)", err, query)
	}

	defer stmt.Close()
	// defer fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 12"))
	rows, err := stmt.Query()
	if err != nil {
		return fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()
	// defer fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 123"))

	count := len(columns)

	for rows.Next() {
		// fmt.Println(">", coloredTableName, text.FgGreen.Sprint("scanning completed 1234"))
		if barchan != nil {
			barchan <- struct{}{}
		}
		values := make([]interface{}, count)
		scanArgs := make([]interface{}, count)
		for i := range values {
			scanArgs[i] = &values[i]
		}

		err := rows.Scan(scanArgs...)
		if err != nil {
			return fmt.Errorf("error scanning row: %v", err)
		}

		for i := range values {

			val := GetValuesString(values[i])
			if val == "" || val == "NULL" || val == "<nil>" {
				continue
			}

			err := p.tableScanManager.PushValue(ScanInput{
				Tablename:  p.tableName,
				ColumnName: columns[i],
				Value:      val,
			})
			if err != nil {
				return fmt.Errorf("error pushing value: %v", err)
			}
		}

	}

	return nil
}

// func (p *piiTableScanner) getColumns() ([]string, error) {
// 	stmt, err := p.store.Prepare("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '" + p.tableName + "';")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer stmt.Close()

// 	rows, err := stmt.Query()
// 	if err != nil {
// 		return nil, err
// 	}

// 	defer rows.Close()

// 	var columns []string
// 	for rows.Next() {
// 		var column string
// 		var columnType string
// 		err := rows.Scan(&column, &columnType)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if !IgnoreColumn(column) && !IgnoreColumnType(columnType) {
// 			columns = append(columns, column)
// 		}
// 	}

// 	return columns, nil
// }

func (p *piiTableScanner) processColumns(ctx context.Context) ([]string, error) {

	stmt, err := p.store.Prepare(fmt.Sprintf(`SELECT * FROM %s limit 0`, p.tableName))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		return nil, fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("error getting columns: %v", err)
	}

	// filter unwanted columns
	columns = FilterColumns(columns)
	if len(columns) == 0 {
		return nil, nil
	}

	for _, column := range columns {
		err := p.tableScanManager.PushColumn(ctx, ScanInput{
			Tablename:  p.tableName,
			ColumnName: column,
		})
		if err != nil {
			return nil, fmt.Errorf("error pushing column: %v", err)
		}
	}

	return columns, nil
}

// func (p *piiTableScanner) processValues(_ context.Context, values map[string]interface{}) error {
// 	for column, value := range values {
// 		err := p.tableScanManager.PushValue(ScanInput{
// 			Tablename:  p.tableName,
// 			ColumnName: column,
// 			Value:      value,
// 		})
// 		if err != nil {
// 			return err
// 		}

// 	}

// 	return nil
// }

// func (p *piiTableScanner) getFinalResult() map[string]PIILabel {
// 	out := make(map[string]PIILabel)

// 	for column, labelScore := range p.result {
// 		maxScore := 0.0
// 		out[column] = ""
// 		for label, score := range labelScore {
// 			if score > maxScore {
// 				maxScore = score
// 				out[column] = label
// 			}
// 		}
// 	}

// 	return out
// }
