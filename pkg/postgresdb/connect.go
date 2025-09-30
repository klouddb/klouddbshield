package postgresdb

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

type Postgres struct {
	Host        string `toml:"host"`
	Port        string `toml:"port"`
	User        string `toml:"user"`
	Password    string `toml:"password"`
	DBName      string `toml:"dbname"`
	SSLmode     string `toml:"sslmode"`
	SSLcert     string `toml:"sslcert"`
	SSLkey      string `toml:"sslkey"`
	SSLrootcert string `toml:"sslrootcert"`
	PingCheck   bool   `toml:"pingCheck"`
	MaxIdleConn int    `toml:"maxIdleConn"`
	MaxOpenConn int    `toml:"maxOpenConn"`
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

// BuildConnectionString builds a PostgreSQL connection string from the given configuration
func BuildConnectionString(conf Postgres) string {
	var parts []string

	parts = append(parts,
		fmt.Sprintf("host=%s", conf.Host),
		fmt.Sprintf("port=%s", conf.Port),
		fmt.Sprintf("user=%s", conf.User),
		fmt.Sprintf("password=%s", conf.Password),
		fmt.Sprintf("dbname=%s", conf.DBName),
	)

	if conf.SSLmode != "" {
		parts = append(parts, fmt.Sprintf("sslmode=%s", conf.SSLmode))
	} else {
		parts = append(parts, "sslmode=disable")
	}
	if conf.SSLcert != "" {
		parts = append(parts, fmt.Sprintf("sslcert=%s", conf.SSLcert))
	}
	if conf.SSLkey != "" {
		parts = append(parts, fmt.Sprintf("sslkey=%s", conf.SSLkey))
	}
	if conf.SSLrootcert != "" {
		parts = append(parts, fmt.Sprintf("sslrootcert=%s", conf.SSLrootcert))
	}

	return strings.Join(parts, " ")
}

func Open(conf Postgres) (*sql.DB, string, error) {
	url := BuildConnectionString(conf)

	db, err := ConnectDatabaseUsingConnectionString(url, conf.PingCheck)
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
func ConnectDatabaseUsingConnectionString(url string, pingCheck bool) (*sql.DB, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Error().
			Err(err).
			Str("conn", url).
			Msg("Failed to open database connection")
		return nil, err
	}

	if pingCheck {
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
