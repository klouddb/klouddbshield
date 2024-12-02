package config

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/spf13/viper"
)

func Test_TomlParsingTest(t *testing.T) {
	tests := []struct {
		name           string
		fileData       string
		wantErr        bool
		expectedOutput *Config
	}{
		{
			name: "Test case 1",
			fileData: `
customTemplate="/path/to/template"

[postgres]
host = "localhost"
port = "5432"
user = "postgres"
password = "password123"
dbname = "mydb"
maxIdleConn = 10
maxOpenConn = 100

[mysql]
host = "localhost"
port = "3306"
user = "root"
password = "password123"
maxIdleConn = 10
maxOpenConn = 100

[app]
debug = true

[email]
host = "smtp.example.com"
port = 587
username = "emailuser@example.com"
password = "emailpassword"

[[crons]]
schedule = "0 3 * * *"
[[crons.commands]]
name = "cleanup"
[[crons.commands.mysql]]
host = "mysql.example.com"
port = "3306"
user = "cronuser"
password = "password"
maxIdleConn = 5
maxOpenConn = 10
[[crons.commands.postgres]]
host = "postgres.example.com"
port = "5432"
user = "cronpguser"
password = "pgpassword"
dbname = "crondb"
maxIdleConn = 5
maxOpenConn = 10
[crons.commands.logparser]
prefix = "log-cleanup"
logfile = "/var/log/cleanup.log"
hbaconffile = "/etc/postgresql/pg_hba.conf"
# cpulimit = 80
`,
			wantErr: false,
			expectedOutput: &Config{
				MySQL: &MySQL{
					Host:        "localhost",
					Port:        "3306",
					User:        "root",
					Password:    "password123",
					MaxIdleConn: 10,
					MaxOpenConn: 100,
				},
				Postgres: &postgresdb.Postgres{
					Host:        "localhost",
					Port:        "5432",
					User:        "postgres",
					Password:    "password123",
					DBName:      "mydb",
					MaxIdleConn: 10,
					MaxOpenConn: 100,
				},
				App: App{
					Debug: true,
				},
				CustomTemplate: "/path/to/template",
				Crons: []Cron{
					{
						Schedule: "0 3 * * *",
						Commands: []Command{
							{
								Name: "cleanup",
								MySQL: []*MySQL{
									{
										Host:        "mysql.example.com",
										Port:        "3306",
										User:        "cronuser",
										Password:    "password",
										MaxIdleConn: 5,
										MaxOpenConn: 10,
									},
								},
								Postgres: []*postgresdb.Postgres{
									{
										Host:        "postgres.example.com",
										Port:        "5432",
										User:        "cronpguser",
										Password:    "pgpassword",
										DBName:      "crondb",
										MaxIdleConn: 5,
										MaxOpenConn: 10,
									},
								},
								LogParser: &LogParserCronInput{
									Prefix:      "log-cleanup",
									LogFile:     "/var/log/cleanup.log",
									HbaConfFile: "/etc/postgresql/pg_hba.conf",
									// CPULimit:    80,
								},
							},
						},
					},
				},
				Email: &AuthConfig{
					Host:     "smtp.example.com",
					Port:     587,
					Username: "emailuser@example.com",
					Password: "emailpassword",
				},
				// PiiScannerConfig can be filled based on your specific configuration needs
				PiiScannerConfig: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("toml")
			err := v.ReadConfig(strings.NewReader(tt.fileData))
			if (err != nil) != tt.wantErr {
				t.Errorf("TomlParsingTest() error = %v", err)
				return
			}

			var cfg Config
			err = v.Unmarshal(&cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("TomlParsingTest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(&cfg, tt.expectedOutput) {
				b, _ := json.Marshal(cfg)
				b1, _ := json.Marshal(tt.expectedOutput)

				fmt.Println(string(b))
				fmt.Println(string(b1))

				t.Errorf("TomlParsingTest() got = %v, want %v", cfg, tt.expectedOutput)
			}
		})
	}
}

func TestCompareConfigFlag(t *testing.T) {
	// Save original command-line arguments and restore them after the test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Set up test arguments
	os.Args = []string{
		"cmd",
		"--compare-config", "postgresql://user1:pass1@host1:5432/db1",
		"--compare-config", "postgresql://user2:pass2@host2:5432/db2",
	}

	// Reset flags for testing
	// flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Call NewConfig
	// config, err := NewConfig()

	// Check for errors
	// if err != nil {
	// 	t.Fatalf("NewConfig returned an error: %v", err)
	// }

	// Check if CompareConfig has the correct values
	// expectedCompareConfig := []string{
	// 	"postgresql://user1:pass1@host1:5432/db1",
	// 	"postgresql://user2:pass2@host2:5432/db2",
	// }

	// if !reflect.DeepEqual(config.CompareConfig, expectedCompareConfig) {
	// 	t.Errorf("CompareConfig does not match expected value. Got %v, want %v", config.CompareConfig, expectedCompareConfig)
	// }
}
