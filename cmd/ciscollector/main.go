package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	internal "github.com/klouddb/klouddbshield/mysql"
	"github.com/klouddb/klouddbshield/pkg/config"

	mysql "github.com/klouddb/klouddbshield/pkg/mysql"
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

	// for _, database := range cnf.Database {
	// Open Postgres store connection and ping it
	database := cnf.Database
	store, _, err := mysql.Open(database)
	if err != nil {
		return
	}
	listOfResults := internal.PerformAllChecks(store, ctx)
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
