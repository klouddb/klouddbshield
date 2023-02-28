package config

import (
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	MySQL    *MySQL    `toml:"mysql"`
	Postgres *Postgres `toml:"postgres"`
	App      App       `toml:"app"`
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

type App struct {
	Debug       bool   `toml:"debug"`
	DryRun      bool   `toml:"dryRun"`
	Hostname    string `toml:"hostname"`
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
	var runPostgres bool
	var runMySql bool
	flag.BoolVar(&run, "r", run, "Run")
	flag.BoolVar(&runMySql, "run-mysql", runMySql, "Run MySQL")
	flag.BoolVar(&runPostgres, "run-postgres", runPostgres, "Run Postgres")
	// flag.BoolVar(&verbose, "v", verbose, "Verbose")
	flag.BoolVar(&version, "version", version, "Print version")

	flag.Parse()

	if version {
		log.Debug().Str("version", Version).Send()
		os.Exit(0)
	}
	if !(run || runMySql || runPostgres) {
		flag.Usage()
		os.Exit(0)
	}
	if run {
		fmt.Println("1.Postgres\n2.MySQL")
		fmt.Printf("Enter your choice to execute(1/2):")
		choice := 0
		fmt.Scanln(&choice)
		switch choice {
		case 1:
			runPostgres = true
		case 2:
			runMySql = true
		default:
			fmt.Println("Invalid Choice, Please Try Again.")
			os.Exit(1)
		}
	}

	c := new(Config)

	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigName("kshieldconfig")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/klouddbshield")

	err := v.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("fatal error config file: %w", err)
	}
	c.App.Run = run
	c.App.RunMySql = runMySql
	c.App.RunPostgres = runPostgres
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
	if c.MySQL == nil && c.Postgres == nil {
		return nil, fmt.Errorf("Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate it with your dbname,username etc.. before using this utility. For additional details please check github readme.")
	}
	if c.MySQL == nil && runMySql {
		return nil, fmt.Errorf("In older version we used [database] label and in current version we are changing it to [mysql] and kindly update your kshieldconfig file(/etc/klouddbshield/kshieldconfig.toml) - See sample entry in readme.")
	}
	if c.Postgres == nil && runPostgres {
		return nil, fmt.Errorf("In older version we used [database] label and in current version we are changing it to [postgres] and kindly update your kshieldconfig file(/etc/klouddbshield/kshieldconfig.toml) - See sample entry in readme.")
	}
	if c.MySQL != nil && c.MySQL.User == "" && runMySql {
		fmt.Printf("Enter Your MySQL DB User: ")
		fmt.Scanln(&c.MySQL.User)
	}
	if c.MySQL != nil && c.MySQL.Password == "" && runMySql {
		fmt.Printf("Enter Your DB MySQL Password for %s: ", c.MySQL.User)
		fmt.Scanln(&c.MySQL.Password)
	}

	if c.Postgres != nil && c.Postgres.User == "" && runPostgres {
		fmt.Printf("Enter Your Postgres DB User: ")
		fmt.Scanln(&c.Postgres.User)
	}
	if c.Postgres != nil && c.Postgres.Password == "" && runPostgres {
		fmt.Printf("Enter Your DB Postgres Password for %s: ", c.Postgres.User)
		fmt.Scanln(&c.Postgres.Password)
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
