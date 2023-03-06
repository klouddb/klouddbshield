package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/mysqldb"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/postgres"
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

	// Program context
	ctx := context.Background()
	if cnf.App.RunMySql {
		runMySql(ctx, cnf)
	}
	if cnf.App.RunPostgres {
		runPostgres(ctx, cnf)
	}
	if cnf.App.RunRds {
		runRDS(ctx, cnf)
	}
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
func runPostgres(ctx context.Context, cnf *config.Config) {
	postgresDatabase := cnf.Postgres
	postgresStore, _, err := postgresdb.Open(*postgresDatabase)
	if err != nil {
		return
	}
	listOfResults := postgres.PerformAllChecks(postgresStore, ctx)
	jsonData, err := json.MarshalIndent(listOfResults, "", "  ")
	if err != nil {
		return
	}
	err = os.WriteFile("postgressecreport.json", jsonData, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate postgressecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
	}
	fmt.Println("postgressecreport.json file generated")
}

func runRDS(ctx context.Context, cnf *config.Config) {
	fmt.Println("running RDS ")
	listOfResults := rds.PerformAllChecks(ctx)

	jsonData, err := json.MarshalIndent(listOfResults, "", "  ")
	if err != nil {
		fmt.Println("error marshaling list of results", err)
		return
	}
	err = os.WriteFile("rdssecreport.json", jsonData, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Unable to generate rdssecreport.json file: " + err.Error())
		fmt.Println("**********listOfResults*************\n", string(jsonData))
	}
	fmt.Println("rdssecreport.json file generated")
}
