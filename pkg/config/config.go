package config

import (
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	MySQL *MySQL `toml:"mysql"`
	// Postgres Postgres `toml:"postgres"`
	// API      API                 `toml:"api"`
	App App `toml:"app"`
}

type Postgres struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	// SSLmode     string `toml:"sslmode"`
	MaxIdleConn int `toml:"maxIdleConn"`
	MaxOpenConn int `toml:"maxOpenConn"`
}
type MySQL struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	// DBName      string `toml:"dbname"`
	// SSLmode     string `toml:"sslmode"`
	MaxIdleConn int `toml:"maxIdleConn"`
	MaxOpenConn int `toml:"maxOpenConn"`
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
	Run         bool
	RunPostgres bool
	RunMySql    bool
}

var CONF *Config

var Version = "dev"

func NewConfig() (*Config, error) {
	// var verbose bool
	var version bool
	var run bool
	// var runPostgres bool
	var runMySql bool
	flag.BoolVar(&run, "r", run, "Run")
	flag.BoolVar(&runMySql, "run-mysql", runMySql, "Run MySQL")
	// flag.BoolVar(&runPostgres, "run-postgres", runPostgres, "Run Postgres")
	// flag.BoolVar(&verbose, "v", verbose, "Verbose")
	flag.BoolVar(&version, "version", version, "Print version")

	flag.Parse()

	if version {
		log.Debug().Str("version", Version).Send()
		os.Exit(0)
	}
	if !(run || runMySql) {
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
	c.App.RunMySql = runMySql
	// c.App.RunPostgres = runPostgres
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
	if c.MySQL == nil {
		return nil, fmt.Errorf("In older version we used [database] label and in current version we are changing it to [mysql] and kindly update your cisconfig file(/etc/mysqlcollector/cisconfig.toml) - See sample entry in readme ")

	}
	if c.MySQL.User == "" {
		fmt.Printf("Enter Your DB User: ")
		fmt.Scanln(&c.MySQL.User)

	}
	if c.MySQL.Password == "" {
		fmt.Printf("Enter Your DB Password for %s: ", c.MySQL.User)
		fmt.Scanln(&c.MySQL.Password)
	}
	CONF = c
	return c, nil
}

func MustNewConfig() *Config {
	config, err := NewConfig()
	if err != nil {
		fmt.Println("Can't create config")
		fmt.Println(err)
		os.Exit(1)
	}

	return config
}
