package mysqldb

import (
	"database/sql"
	"fmt"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/rs/zerolog/log"

	_ "github.com/go-sql-driver/mysql"
)

// Open opens a the postgres database connection specified by its connection
// url which can be of format:
// https://pkg.go.dev/github.com/lib/pq#hdr-Connection_String_Parameters

// var re = regexp.MustCompile(`(?m)(?:host=)([^\s]+)`)

func Open(conf config.MySQL) (*sql.DB, string, error) {
	url := fmt.Sprintf("%s:%s@tcp(%s:%s)/", conf.User, conf.Password, conf.Host, conf.Port)
	// db, err := sql.Open("mysql", `root:mysql111@tcp(localhost:3306)/mysql`)
	//	log.Print(url)
	db, err := sql.Open("mysql", url)
	if err != nil {
		log.Error().
			Err(err).
			Str("conn", url).
			Msg("Failed to connect to database")
		return nil, "", err
	}

	if conf.PingCheck {
		err = db.Ping()
		if err != nil {
			// fmt.Printf("Failed to connect to database. Error:	%s", err.Error())
			return nil, "", err
		}
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

	// Extract hostname from connection string

	var hostname string
	if len(conf.Host) < 2 {
		log.Error().Msg("Failed to extract hostname from connection string")
		hostname = "unknown"
	} else {
		hostname = conf.Host
	}

	return db, hostname, nil
}
