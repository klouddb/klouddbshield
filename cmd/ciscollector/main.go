package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/mysqldb"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/klouddb/klouddbshield/postgres/hbascanner"
	"github.com/klouddb/klouddbshield/rds"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	// Init logger
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC1123Z}
	log.Logger = zerolog.New(consoleWriter).With().Timestamp().Caller().Logger()
	log.Logger.Level(zerolog.TraceLevel)
}

func main() {
	cnf := config.MustNewConfig()
	// Setup log level
	if !cnf.App.Debug {
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	}

	htmlHelper := &htmlreport.HTMLHelper{}
	defer func() {
		htmlHelper.Generate("report.html", 0600)
		fmt.Println("html report generated")
	}()

	// Program context
	ctx := context.Background()
	if cnf.App.VerbosePostgres {
		runPostgresByControl(ctx, cnf)

	}
	if cnf.App.RunMySql {
		runMySql(ctx, cnf)
	}
	if cnf.App.RunPostgres {
		runPostgres(ctx, cnf, htmlHelper)

	}
	if cnf.App.RunRds {
		runRDS(ctx, cnf)
	}
	if cnf.App.HBASacanner {
		runHBAScanner(ctx, cnf, htmlHelper)
	}
	if cnf.App.VerboseHBASacanner {
		runHBAScannerByControl(ctx, cnf)
	}

}
func runPostgresByControl(ctx context.Context, cnf *config.Config) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return
	}
	result := postgres.CheckByControl(postgresStore, ctx, cnf.App.Control)
	if result == nil {
		os.Exit(1)
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if result.Status == "Pass" {
		t.AppendSeparator()
		color := text.FgGreen
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})

	} else {
		t.AppendSeparator()
		color := text.FgRed
		t.AppendRow(table.Row{"Status", color.Sprintf("%s", result.Status)})
		t.AppendSeparator()
		switch ty := result.FailReason.(type) {

		case string:

			t.AppendRow(table.Row{"Fail Reason", result.FailReason})
		case []map[string]interface{}:
			failReason := ""
			for _, n := range ty {
				for key, value := range n {
					failReason += fmt.Sprintf("%s:%v, ", key, value)
				}
				failReason += "\n"

			}
			t.AppendRow(table.Row{"Fail Reason", failReason})
		default:
			var r = reflect.TypeOf(t)
			fmt.Printf("Other:%v\n", r)
		}

	}
	t.AppendSeparator()
	t.AppendRow(table.Row{"Rationale", result.Rationale})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Title", result.Title})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Procedure", result.Procedure})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Control", result.Control})
	t.AppendSeparator()
	t.AppendRow(table.Row{"References", result.References})
	t.SetStyle(table.StyleLight)
	t.Render()
}
func runMySql(ctx context.Context, cnf *config.Config) {
	// for _, mySQL := range cnf.MySQL {
	// Open Postgres store connection and ping it
	mysqlDatabase := cnf.MySQL
	mysqlStore, _, err := mysqldb.Open(*mysqlDatabase)
	if err != nil {
		return
	}
	listOfResults := mysql.PerformAllChecks(mysqlStore, ctx)
	jsonData, err := json.MarshalIndent(listOfResults, "", "  ")
	if err != nil {
		return
	}
	err = os.WriteFile("mysqlsecreport.json", jsonData, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate mysqlsecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
	}
	fmt.Println("mysqlsecreport.json file generated")
	// }
}
func runPostgres(ctx context.Context, cnf *config.Config, h *htmlreport.HTMLHelper) []*model.Result {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return nil
	}
	listOfResults := postgres.PerformAllChecks(postgresStore, ctx)
	jsonData, err := json.MarshalIndent(listOfResults, "", "  ")
	if err != nil {
		return nil
	}

	err = os.WriteFile("postgressecreport.json", jsonData, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate postgressecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
	}
	fmt.Println("postgressecreport.json file generated")
	data := htmlreport.GenerateHTMLReport(listOfResults, "Postgres")
	h.AddTab("Postgres", data)
	// data = htmlreport.GenerateMarkdown(listOfResults)
	// htmldata = []byte(data)
	// err = os.WriteFile("postgressecreport.md", htmldata, 0600)
	// if err != nil {
	// 	log.Error().Err(err).Msg("Unable to generate postgressecreport.md file: " + err.Error())
	// 	fmt.Println("**********listOfResults*************\n", data)
	// }
	// fmt.Println("postgressecreport.md file generated")
	return listOfResults

}

func runRDS(ctx context.Context, cnf *config.Config) {
	fmt.Println("running RDS ")
	rds.Validate()
	listOfResults := rds.PerformAllChecks(ctx)

	jsonData, err := json.MarshalIndent(listOfResults, "", "  ")
	if err != nil {
		fmt.Println("error marshaling list of results", err)
		return
	}

	output := strings.ReplaceAll(string(jsonData), `\n`, "\n")

	// write output data to file
	err = os.WriteFile("rdssecreport.json", []byte(output), 0600)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate rdssecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
	}
	fmt.Println("rdssecreport.json file generated")
}
func runHBAScanner(ctx context.Context, cnf *config.Config, h *htmlreport.HTMLHelper) []*model.HBAScannerResult {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return nil
	}
	listOfResults := hbascanner.HBAScanner(postgresStore, ctx)

	data := htmlreport.GenerateHTMLReportForHBA(listOfResults)
	h.AddTab("HSB Scanner Report", data)
	for i := 0; i < len(listOfResults); i++ {
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\t", " ")
		listOfResults[i].Procedure = strings.ReplaceAll(listOfResults[i].Procedure, "\n", " ")
		if listOfResults[i].FailRows != nil {
			for j := 0; j < len(listOfResults[i].FailRows); j++ {
				listOfResults[i].FailRows[j] = strings.ReplaceAll(listOfResults[i].FailRows[j], "\t", " ")
			}
		}
	}

	jsonData, err := json.MarshalIndent(listOfResults, "", "  ")
	if err != nil {
		return nil
	}
	err = os.WriteFile("hbascannerreport.json", jsonData, 0002)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate hbascannerreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
	}
	fmt.Println("hbascannerreport.json file generated")
	return listOfResults
}
func runHBAScannerByControl(ctx context.Context, cnf *config.Config) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return
	}
	result := hbascanner.HBAScannerByControl(postgresStore, ctx, cnf.App.Control)
	if result == nil {
		os.Exit(1)
	}

}
