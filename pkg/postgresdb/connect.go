package postgresdb

import (
	"database/sql"
	"fmt"
	"regexp"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

type Postgres struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	SSLmode     string `toml:"sslmode"`
	PingCheck	  bool `toml:"pingCheck"`
	MaxIdleConn int `toml:"maxIdleConn"`
	MaxOpenConn int `toml:"maxOpenConn"`
}

func (p *Postgres) HtmlReportName() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("postgres_%s:%s_%s", p.Host, p.Port, p.DBName)
}

// Open opens a the postgres database connection specified by its connection
// url which can be of format:
// https://pkg.go.dev/github.com/lib/pq#hdr-Connection_String_Parameters

var re = regexp.MustCompile(`(?m)(?:host=)([^\s]+)`)

func Open(conf Postgres) (*sql.DB, string, error) {
	// "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable"
	url := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", conf.Host, conf.Port, conf.User, conf.Password, conf.DBName)

	db, err := ConnectDatabaseUsingConnectionString(url)
	if err != nil {
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

// ConnectDatabaseUsingConnectionString connects to a PostgreSQL database using the provided connection string.
// It returns a database connection, the connection string, and an error if any.
func ConnectDatabaseUsingConnectionString(url string) (*sql.DB, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Error().
			Err(err).
			Str("conn", url).
			Msg("Failed to open database connection")
		return nil, err
	}

	if conf.PingCheck {
		err = db.Ping()
		if err != nil {
			log.Error().
				Err(err).
				Str("conn", url).
				Msg("Failed to ping database")
			db.Close()
			return nil, err
		}
	}

	return db, nil
}
