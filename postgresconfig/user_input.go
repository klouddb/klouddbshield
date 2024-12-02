package postgresconfig

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"regexp"

	"github.com/jedib0t/go-pretty/v6/text"
)

type node struct {
	label       string
	helpMessage string
	options     []string
	validation  func(m map[string]string, val string) error
	setFunc     func(m map[string]string, val string) error
	skipFunc    func(m map[string]string) (bool, error)
}

type processor struct {
	data           map[string]string
	nodes          []*node
	configDir      string
	withoutSummary bool
}

func NewProcessor(configDir string) *processor {
	return &processor{
		data: map[string]string{},
		nodes: []*node{
			{
				label:       "Would you like to use Advanced mode? " + text.FgGreen.Sprint("recommended for production systems") + " may take 5-10 minutes",
				helpMessage: "Y/n",
				validation:  validateBool,
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "no" {
						return nil
					}

					m["listen_addr"] = "*" // Set defaults for quick mode
					m["port"] = "5432"
					m["superuser_reserved_connections"] = "3"
					m["wal_level"] = "replica"
					m["synchronous_commit"] = "ON"
					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "Which PostgreSQL version are you using?",
				helpMessage: "Enter a number (e.g., 13, 14, 15, or 16)",
				validation:  validateInt,
				setFunc:     fieldSetFunction("version"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "How much RAM does your system have?",
				helpMessage: "Enter a value followed by GB or TB (e.g., 4GB, 8GB, 1TB)",
				validation:  validateRegExp(regexp.MustCompile(`^[1-9]\d*(?:GB|TB)$`)),
				setFunc:     fieldSetFunction("ram"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "How many CPU cores does your system have?",
				helpMessage: "Enter a number between 1 and 72",
				validation:  validateIntRange(1, 72),
				setFunc:     fieldSetFunction("cpu"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:      "What type of storage are you using?",
				options:    []string{"SSD", "HDD", "Network (SAN)"},
				validation: EmptyValidationfunc,
				setFunc: func(m map[string]string, val string) error {
					switch val {
					case "SSD":
						m["diskType"] = fmt.Sprint(DiskType_SSD)
					case "HDD":
						m["diskType"] = fmt.Sprint(DiskType_HDD)
					case "Network (SAN)":
						m["diskType"] = fmt.Sprint(DiskType_SAN)
					default:
						return fmt.Errorf("invalid disk type")
					}

					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "What is the total size of your database?",
				helpMessage: "Enter a value followed by GB or TB (e.g., 100GB, 1TB, 10TB)",
				validation:  validateRegExp(regexp.MustCompile(`^[1-9]\d*(?:GB|TB)$`)),
				setFunc:     fieldSetFunction("databaseSize"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:      "What is the primary use case for your database?",
				options:    []string{"Web application", "OLTP", "Data warehouse", "Desktop application", "Mixed workload"},
				validation: EmptyValidationfunc,
				setFunc: func(m map[string]string, val string) error {
					switch val {
					case "Web application":
						m["dbType"] = "1"
					case "OLTP":
						m["dbType"] = "2"
					case "Data warehouse":
						m["dbType"] = "3"
					case "Desktop application":
						m["dbType"] = "4"
					case "Mixed workload":
						m["dbType"] = "5"
					}
					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "How many database replicas do you have?",
				helpMessage: "Enter a non-negative integer (0 for no replicas)",
				validation:  validateIntRange(0, math.MaxInt64),
				setFunc:     fieldSetFunction("replica"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Enter a valid IP address or * for all",
				helpMessage: "e.g 43.23.54.10 or *",
				validation:  validateRegExp(regexp.MustCompile(`^(?:\*|(?:[0-9]{1,3}\.){3}[0-9]{1,3})?$`)),
				setFunc:     fieldSetFunctionDefault("listen_addr", "*"),
				skipFunc:    skipIfSetFieldFunction("listen_addr"),
			},
			{
				label:       "Enter a valid port. Avoid using 5432 for better security.",
				helpMessage: "e.g 1234 (1-65535)",
				validation:  validateIntRange(1, 65535),
				setFunc:     fieldSetFunction("port"),
				skipFunc:    skipIfSetFieldFunction("port"),
			},
			{
				label:       "superuser reserved connections",
				helpMessage: "greater than 3.",
				validation:  validateIntRange(3, math.MaxInt),
				setFunc:     fieldSetFunctionDefault("superuser_reserved_connections", "3"),
				skipFunc:    skipIfSetFieldFunction("superuser_reserved_connections"),
			},
			{
				label:       "Set the maximum WAL (Write-Ahead Log) size",
				helpMessage: "Enter a value in MB. Recommended: at least 3x the WAL generated during a 15-minute peak period",
				validation:  validateIntRange(2, 2147483647),
				setFunc:     fieldSetFunction("max_wal_size"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Enable WAL compression?",
				helpMessage: "y/N",
				validation:  validateBool,
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "yes" {
						m["wal_compression"] = "on"
					} else {
						m["wal_compression"] = "off"
					}
					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "Are you going to use logical replication?",
				helpMessage: "y/N",
				validation:  validateBool,
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "yes" {
						m["wal_level"] = "logical"
					}
					return nil
				},
				skipFunc: skipIfSetFieldFunction("wal_level"),
			},
			{
				label:       "Is this a test environment?",
				helpMessage: "y/N",
				validation:  validateBool,
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) != "yes" {
						m["wal_level"] = "minimal"
					}
					return nil
				},
				skipFunc: skipIfSetFieldFunction("wal_level"),
			},
			{
				label:       "Do you need WAL archival?",
				helpMessage: "y/N",
				validation:  validateBool,
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "yes" {
						m["wal_level"] = "replica"
					} else {
						m["wal_level"] = "minimal"
					}
					return nil
				},
				skipFunc: skipIfSetFieldFunction("wal_level"),
			},
			{
				label:       "Would you like to set synchronous_commit to ON?",
				helpMessage: "Recommended if you want avoid losing any transactions (y/N)",
				validation:  validateBool,
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "yes" {
						m["synchronous_commit"] = "ON"
					} else {
						m["synchronous_commit"] = "OFF"
					}
					return nil
				},
				skipFunc: skipIfSetFieldFunction("synchronous_commit"),
			},
			{
				label:       "Include replicas/standbys",
				helpMessage: "e.g ANY(s1, s2, s3) or FIRST(s1, s2) or '*' to include all standby servers",
				validation: validateRegExp(
					regexp.MustCompile(`(?i)(?:(?:^(?:first|any)\(.+\)$)|(?:^(?:\*)?$))`),
				),
				setFunc:  fieldSetFunctionDefault("synchronous_standby_names", "*"),
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "Set temp_file_limit to prevent large temporary files (recommended: 1GB-2GB). This prevents disk full errors and other issues. Default: 1GB. For more information, visit: https://klouddb.io/temporary-files-in-postgresql-steps-to-identify-and-fix-temp-file-issues/",
				helpMessage: "Specify a value (e.g., 1GB or 2GB) to limit temporary file size.",
				validation:  validateRegExp(regexp.MustCompile(`^(?:[1-9]\d*(?:GB|TB))?$`)),
				setFunc:     fieldSetFunctionDefault("temp_file_limit", "1GB"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Specify the minimum delay between autovacuum runs (default: 1 minute). Decrease to 30s or 15s for large number of tables.",
				helpMessage: "Value in milliseconds (ms). Default: 60",
				validation:  validateIntRangeAllowEmpty(1, 2147483),
				setFunc:     fieldSetFunctionDefault("autovacuum_naptime", "60"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Set autovacuum_vacuum_cost_limit to control vacuum resource usage. Too high may slow queries, too low may not reclaim space.",
				helpMessage: "Accumulated cost causing vacuum to sleep for cost_delay time. Default: -1 (ms)",
				validation:  validateIntRangeAllowEmpty(-1, 10000),
				setFunc:     fieldSetFunctionDefault("autovacuum_vacuum_cost_limit", "-1"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Specify autovacuum_vacuum_cost_delay (in ms) to pause autovacuum job when autovacuum_vacuum_cost_limit is reached. Default is 2 ms. Override only if you have vacuuming issues.",
				helpMessage: "Enter a value in milliseconds (ms). Default: 2 ms",
				validation:  validateIntRangeAllowEmpty(-1, 100),
				setFunc:     fieldSetFunctionDefault("autovacuum_vacuum_cost_delay", "2"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Increase this value if you have a large number of tables and sufficient CPU cores",
				helpMessage: "Note: Stick with the default unless you have vacuuming issues. Value in milliseconds (ms). Default: 3",
				validation:  validateIntRangeAllowEmpty(1, 262143),
				setFunc:     fieldSetFunctionDefault("autovacuum_max_workers", "3"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Recommended JIT setting: 'off' for OLTP/web apps, 'on' for data warehouses. Benchmark critical apps to find the best setting.",
				helpMessage: "Default: 'off'",
				validation:  validateRegExp(regexp.MustCompile(`(?i)^(?:on|off)?$`)),
				setFunc:     fieldSetFunctionDefault("jit", "off"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Set statement_timeout (in milliseconds) to abort long-running queries. For OLTP apps, 60000 ms (60s) is recommended",
				validation:  validateIntRangeAllowEmpty(0, 2147483647),
				helpMessage: "Default: 60000 ms (60s). Range: 0-2147483647 ms",
				setFunc:     fieldSetFunctionDefault("statement_timeout", "60000"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "Terminate any session idle in an open transaction for longer than the specified time (default: 30 minutes)",
				helpMessage: "Value in milliseconds (ms). Default: 1800000 ms",
				validation:  validateIntRangeAllowEmpty(0, 2147483647),
				setFunc:     fieldSetFunctionDefault("idle_in_transaction_session_timeout", "1800000"),
				skipFunc:    EmptySkipFunc,
			},
		},
		configDir: configDir,
	}
}

func (p *processor) WithoutSummary() *processor {
	p.withoutSummary = true
	return p
}

func (p *processor) GetSummary() error {
	if p.withoutSummary {
		return nil
	}

	summary, err := GenerateSummary(p.GetData())
	if err != nil {
		return err
	}

	fmt.Println(summary)
	fmt.Print("Please review the above summary and press enter to continue or Ctrl+C to exit.")
	fmt.Scanln() //nolint:errcheck

	return nil
}

func (p *processor) GetData() map[string]string {
	return p.data
}

func (p *processor) Run(ctx context.Context) error {
	err := p.GetUserInput(ctx)
	if err != nil {
		return err
	}

	err = p.GetSummary()
	if err != nil {
		return err
	}

	return p.GenerateConfigFile(filepath.Join(p.configDir, "postgresql.conf"))
}

func (p *processor) GetUserInput(ctx context.Context) error {
	for _, n := range p.nodes {
		skip, err := n.skipFunc(p.data)
		if err != nil {
			return err
		}

		if skip {
			continue
		}

		fmt.Print("\033[H\033[2J") // Clear terminal
		fmt.Printf("> %s: ", n.label)
		if len(n.helpMessage) != 0 {
			fmt.Printf("[%s] : ", text.FgHiCyan.Sprint(n.helpMessage))
		}
		var userInput string
		i := 0
		for ; i < 3; i++ {
			userInput = ""
			if len(n.options) == 0 {
				fmt.Scanln(&userInput) //nolint:errcheck
			} else {
				fmt.Println()
				for i, v := range n.options {
					fmt.Println("\t" + text.Bold.Sprint(i+1) + ". " + v)
				}

				// wait for user input
				fmt.Print("Select one from the list :")
				var val int
				fmt.Scanf("%d", &val) //nolint:errcheck

				if val > len(n.options) || val <= 0 {
					// invalid value
					fmt.Println("invalid option selected. please retry")
					continue
				}
				userInput = n.options[val-1]
			}

			err := n.validation(p.data, userInput)
			if err == nil {
				break
			}

			if i < 2 {
				fmt.Printf(
					"You have added invalid input. Error: %v\nTry again (available retries: %d) :",
					text.FgRed.Sprint(err),
					2-i,
				)
			}
		}
		if i == 3 {
			return fmt.Errorf("reached maximum retry limit")
		}

		err = n.setFunc(p.data, userInput)
		if err != nil {
			return err
		}
	}

	fmt.Print("\033[H\033[2J") // Clear terminal

	return nil
}

func (p *processor) GenerateConfigFile(filepath string) error {
	configString := ConfigGenerator(p.GetData())

	return WriteToFile(configString, filepath)
}
