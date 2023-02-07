package config

import (
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	Database Database `toml:"database"`
	// API      API                 `toml:"api"`
	App App `toml:"app"`
}

type Database struct {
	Host        string `toml:"host"`
	Port        string `toml:"port"`
	User        string `toml:"user"`
	Password    string `toml:"password"`
	DBName      string `toml:"dbname"`
	SSLmode     string `toml:"sslmode"`
	MaxIdleConn int    `toml:"maxIdleConn"`
	MaxOpenConn int    `toml:"maxOpenConn"`
}

// type API struct {
// 	URL string `toml:"url"`
// 	Key string `toml:"key"`
// }

type App struct {
	Debug    bool   `toml:"debug"`
	DryRun   bool   `toml:"dryRun"`
	Hostname string `toml:"hostname"`
	// CollectorCron string `toml:"collectorCron"`
	// ControlCron   string `toml:"controlCron"`
	// ReplicaCron   string `toml:"replicaCron"`
	Run bool
}

var CONF *Config

var Version = "dev"

func NewConfig() (*Config, error) {
	// var verbose bool
	var version bool
	var run bool
	flag.BoolVar(&run, "r", run, "Run")
	// flag.BoolVar(&verbose, "v", verbose, "Verbose")
	flag.BoolVar(&version, "version", version, "Print version")

	flag.Parse()

	if version {
		log.Debug().Str("version", Version).Send()
		os.Exit(0)
	}
	if !run {
		flag.Usage()
		os.Exit(0)
	}

	c := new(Config)

	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigName("cisconfig")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/mysqlcollector")

	err := v.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("fatal error config file: %w", err)
	}
	c.App.Run = run
	err = v.Unmarshal(c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	if c.App.Hostname == "" {
		c.App.Hostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("getting hostname: %w", err)
		}
	}
	// log.Printf("%+v", c.Database)
	if c.Database.User == "" {
		fmt.Printf("Enter Your DB User: ")
		fmt.Scanln(&c.Database.User)

	}
	if c.Database.Password == "" {
		fmt.Printf("Enter Your DB Password for %s: ", c.Database.User)
		fmt.Scanln(&c.Database.Password)
	}
	CONF = c
	return c, nil
}

func MustNewConfig() *Config {
	config, err := NewConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Can't create config")
	}

	return config
}
