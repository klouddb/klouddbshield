package postgresdb

import (
	"database/sql"
	"fmt"
	"regexp"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"

	"github.com/klouddb/klouddbshield/pkg/config"
)

// Open opens a the postgres database connection specified by its connection
// url which can be of format:
// https://pkg.go.dev/github.com/lib/pq#hdr-Connection_String_Parameters

var re = regexp.MustCompile(`(?m)(?:host=)([^\s]+)`)

func Open(conf config.Postgres) (*sql.DB, string, error) {
	// "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable"
	url := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", conf.Host, conf.Port, conf.User, conf.Password, conf.DBName)

	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Error().
			Err(err).
			Str("conn", url).
			Msg("Failed to connect to database")
		return nil, "", err
	}
	err = db.Ping()
	if err != nil {
		fmt.Printf("Failed to connect to database. Error:	%s", err.Error())
		return nil, "", err
	}
	if conf.MaxIdleConn > 0 {
		db.SetMaxIdleConns(conf.MaxIdleConn)
	}
	if conf.MaxOpenConn > 0 {
		db.SetMaxOpenConns(conf.MaxOpenConn)
	}

	// log.Info().
	// 	Int("Max open connections", conf.MaxOpenConn).
	// 	Int("Max idle connections", conf.MaxIdleConn).
	// 	Msg("Database connected successfully")
	// fmt.Println("Database connected successfully")
	// Extract hostname from connection string
	hostnameGroup := re.FindStringSubmatch(url)
	var hostname string
	if len(hostnameGroup) < 2 {
		log.Error().Msg("Failed to extract hostname from connection string")
		hostname = "unknown"
	} else {
		hostname = hostnameGroup[1]
	}

	return db, hostname, nil
}
