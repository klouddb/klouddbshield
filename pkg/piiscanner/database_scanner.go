package piiscanner

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
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
	Region   string

	printAllResults  bool
	spacyOnly        bool
	PrintSummaryOnly bool
}

func NewConfig(pgConfig *postgresdb.Postgres, runOption, excludeTable, includeTable, database, schema string,
	printAllResults, spacyOnly, printSummaryOnly bool) (*Config, error) {
	return NewConfigWithRegion(pgConfig, runOption, excludeTable, includeTable, database, schema, "",
		printAllResults, spacyOnly, printSummaryOnly)
}

// NewConfigWithRegion is like NewConfig but also accepts a PII region.
// When region is "india", the scanner uses exact dpdpa_pii_db_scanner detection logic.
// When region is empty/unset, legacy entity set is used (with updated credit-card handling only).
func NewConfigWithRegion(pgConfig *postgresdb.Postgres, runOption, excludeTable, includeTable, database, schema, region string,
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

	region = strings.TrimSpace(region)
	if region != "" && !IsIndiaRegion(region) {
		return nil, fmt.Errorf("invalid pii region %q, supported values are %q or empty", region, RegionIndia)
	}
	if IsIndiaRegion(region) {
		region = RegionIndia
	} else {
		region = ""
	}

	out := &Config{
		runOption:        r,
		useSpacy:         useSpacy,
		Database:         database,
		Schema:           schema,
		Region:           region,
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
		detectors = append(detectors, NewRegexValueDetectorForRegion(d.cnf.Region))
	}

	if d.cnf.useSpacy {
		spacy := NewSpacyDetector().WithWorkDirs(SpacyWorkDirs)
		if IsIndiaRegion(d.cnf.Region) {
			spacy = spacy.WithColumnContextGate(true)
		}
		detectors = append(detectors, spacy)
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

	d.tableScanManager = NewTableScanManager().WithColumnDetector(NewRegexColumnDetectorForRegion(d.cnf.Region))
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

			hasColumnMatch := false
			for _, piiData := range piiMap.ColumnMap {
				if len(piiData) > 0 {
					hasColumnMatch = true
					break
				}
			}

			for detector, piiData := range piiMap.ColumnMap {
				for label, pii := range piiData {
					piiDataWithWeight := NewPIIDataWithWeightString(label, pii.Weight, DetectorType_ColumnDetector, detector)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			count := d.tableScanManager.ValueCount(table.TableName, columnName)
			weightMergeEntities := WeightMergeEntities(d.cnf.Region)
			indiaMode := IsIndiaRegion(d.cnf.Region)
			for detector, piiData := range piiMap.ValueMap {
				for label, pii := range piiData {
					var finalWeight float64
					if count != 0 {
						finalWeight = pii.Weight / float64(count)
					}

					if weightMergeEntities.Contains(label) {
						columnWeight := piiMap.ColumnMap["regex"][label].Weight
						if indiaMode {
							finalWeight = dpdpa.MergeIndiaValueWeight(string(label), columnWeight, finalWeight)
						} else {
							finalWeight = MergeLegacyValueWeight(columnWeight, finalWeight)
						}
					}

					piiDataWithWeight := NewPIIDataWithWeightString(label, finalWeight, DetectorType_ValueDetector, detector)
					piiDataWithWeight.SetScanedValueAndMatchCount(pii.Count, count)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			SortColumnFindings(output.Data[table.TableName][columnName])

			// India Phase-2/3 unrecognized-column fallbacks — logic lives in DPDPA.
			if indiaMode {
				existingLabels := make([]string, 0, len(output.Data[table.TableName][columnName]))
				for _, item := range output.Data[table.TableName][columnName] {
					existingLabels = append(existingLabels, string(item.Label))
				}
				sampleVals := d.tableScanManager.UnrecognizedValues[table.TableName][columnName]
				fallbacks, err := dpdpa.RunIndiaUnrecognizedColumnFallbacks(
					context.TODO(),
					sampleVals,
					hasColumnMatch,
					existingLabels,
				)
				if err == nil {
					for _, f := range fallbacks {
						piiDataWithWeight := NewPIIDataWithWeightString(PIILabel(f.Label), f.Weight, DetectorType_ValueDetector, "regex")
						piiDataWithWeight.SetScanedValueAndMatchCount(f.MatchedCount, f.ScannedCount)
						output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
					}
				}
			}

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
