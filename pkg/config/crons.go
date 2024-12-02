package config

import (
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

type Cron struct {
	Schedule string    `toml:"schedule"`
	Commands []Command `toml:"commands"`
}

type Command struct {
	Name      string                 `toml:"name"`
	MySQL     []*MySQL               `toml:"mysql"`
	Postgres  []*postgresdb.Postgres `toml:"postgres"`
	LogParser *LogParserCronInput    `toml:"logparser"`
}

type PostgresWithLogparser struct {
	Postgres postgresdb.Postgres
}

type LogParserCronInput struct {
	Prefix      string `toml:"prefix"`
	LogFile     string `toml:"logfile"`
	HbaConfFile string `toml:"hbaconffile"`
	// CPULimit    int    `toml:"cpulimit"`
}
