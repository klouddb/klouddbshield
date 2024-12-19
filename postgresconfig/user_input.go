package postgresconfig

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

type node struct {
	heading      string
	label        string
	helpMessage  string
	extraMessage string
	options      []string
	validation   func(m map[string]string, val string) error
	setFunc      func(m map[string]string, val string) error
	skipFunc     func(m map[string]string) (bool, error)
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
			// {
			// 	label:       "Would you like to use Advanced mode? " + text.FgGreen.Sprint("recommended for production systems") + " may take 5-10 minutes",
			// 	helpMessage: "Y/n",
			// 	validation:  validateBool,
			// 	setFunc: func(m map[string]string, val string) error {
			// 		if simplifyBoolVal(val) == "no" {
			// 			return nil
			// 		}

			// 		m["listen_addr"] = "*" // Set defaults for quick mode
			// 		m["port"] = "5432"
			// 		m["superuser_reserved_connections"] = "3"
			// 		m["wal_level"] = "replica"
			// 		m["synchronous_commit"] = "ON"
			// 		return nil
			// 	},
			// 	skipFunc: EmptySkipFunc,
			// },
			{
				label:       "Which PostgreSQL version are you using?",
				helpMessage: "Enter a number (e.g., 13, 14, 15, or 16)",
				validation:  validateInt,
				setFunc:     fieldSetFunction("version"),
				skipFunc:    EmptySkipFunc,
			},
			{
				label:       "How much RAM does your system have?",
				helpMessage: "Enter a value followed by MB, GB or TB (e.g., 256MB, 8GB, 1TB)",
				validation:  validateSize,
				setFunc:     fieldSetSize("ram"),
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
				label:       "What type of storage are you using?",
				options:     []string{"SSD", "HDD", "Network (SAN)"},
				helpMessage: "Enter a number between 1 and 3",
				validation:  EmptyValidationfunc,
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
			// {
			// 	label:       "What is the total size of your database?",
			// 	helpMessage: "Enter a value followed by GB or TB (e.g., 100GB, 1TB, 10TB)",
			// 	validation:  validateSize,
			// 	setFunc:     fieldSetSize("databaseSize"),
			// 	skipFunc:    EmptySkipFunc,
			// },
			{
				label:       "What is the primary use case for your database?",
				options:     []string{"Web application", "OLTP", "Data warehouse", "Desktop application", "Mixed workload"},
				helpMessage: "Enter a number between 1 and 5",
				validation:  EmptyValidationfunc,
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
				label:       "Listen_addresses parameter : Enter valid IP address or * for all",
				helpMessage: "e.g 43.23.54.10 , Default: *",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - By default, we use * for the listen_addr parameter, but we recommend specifying an IP address range or particular IP addresses for better security. Allowing * opens access to all IPs, which is not a secure practice"),
				),
				validation: validIP,
				setFunc:    fieldSetFunctionDefault("listen_addr", "*"),
				skipFunc:   skipIfSetFieldFunction("listen_addr"),
			},
			{
				label:        "Enter a valid port. Avoid using 5432 for better security.",
				helpMessage:  "e.g 1234 (1-65535). Default: 5432",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation:   validateIntRangeAllowEmpty(1, 65535),
				setFunc:      fieldSetFunctionDefault("port", "5432"),
				skipFunc:     skipIfSetFieldFunction("port"),
			},
			{
				label:        "superuser reserved connections-Sets the number of connection slots reserved for superusers",
				helpMessage:  "greater than 3. Default: 3",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation:   validateIntRangeAllowEmpty(3, math.MaxInt),
				setFunc:      fieldSetFunctionDefault("superuser_reserved_connections", "3"),
				skipFunc:     skipIfSetFieldFunction("superuser_reserved_connections"),
			},
			{
				label:       "Set the maximum WAL (Write-Ahead Log) size",
				helpMessage: "Enter a value in MB or GB, Default: 1GB",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - The max_wal_size parameter is critical for performance. It should be set to at least three times the amount of WALs generated during a 15-minute peak traffic period. Note: This assumes the checkpoint_timeout is set to 15 minutes"),
				),
				validation: validateRegExp(
					regexp.MustCompile(`^(?:\s*[1-9]\d*\s*(?:MB|GB|TB|M|G|T|Mb|Gb|Tb|mB|gB|tB|mb|gb|tb))?$`),
					"input data is not a valid file size",
				),
				setFunc:  fieldSetSizeInMB("max_wal_size", "1024"),
				skipFunc: EmptySkipFunc,
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
					"input data is not a valid replica/standbys",
				),
				setFunc:  fieldSetFunctionDefault("synchronous_standby_names", "*"),
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "Set temp_file_limit to prevent large temporary files (recommended: 1GB-2GB). This prevents disk full errors and other issues. Default: 1GB. For more information, visit: https://klouddb.io/temporary-files-in-postgresql-steps-to-identify-and-fix-temp-file-issues/",
				helpMessage: "Specify a value (e.g., 1GB or 2GB) to limit temporary file size.",
				validation: validateRegExp(
					regexp.MustCompile(`^(?:\s*[1-9]\d*\s*(?:GB|TB|Gb|Tb|gb|tb))?$`),
					"input data is not a valid file size",
				),
				setFunc:  fieldSetSizeDefault("temp_file_limit", "1GB"),
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "Would you like to fine-tune your autovacuum settings?",
				helpMessage: "y/N",
				validation:  validateBool,
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default values>"),
					text.FgHiYellow.Sprint("NOTE - For critical environments, especially if you’re experiencing autovacuum issues or anticipate them, it’s recommended to fine-tune the settings"),
				),
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "yes" {
						return nil
					}

					// Set defaults
					m["autovacuum_naptime"] = "60"
					m["autovacuum_vacuum_cost_limit"] = "-1"
					m["autovacuum_vacuum_cost_delay"] = "2"
					m["autovacuum_max_workers"] = "3"
					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				label:       "Specify the minimum delay between autovacuum runs",
				helpMessage: "Value in milliseconds (ms). Default: 1 minute",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - This parameter specifies the minimum delay between autovacuum runs on any given database. Default is 1 minute , decrease this to 30s or 15s if you have a large number (100's) of tables.. If you want to override the default please specify a value or else hit enter"),
				),
				validation: validateIntRangeAllowEmpty(1, 2147483),
				setFunc:    fieldSetFunctionDefault("autovacuum_naptime", "60"),
				skipFunc:   skipIfSetFieldFunction("autovacuum_naptime"),
			},
			{
				label:       "Set autovacuum_vacuum_cost_limit to control vacuum resource usage",
				helpMessage: "Value in milliseconds (ms). Default: -1 (ms)",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - This is the accumulated cost that will cause the vacuuming process to sleep for cost_delay time .If you set the value of autovacuum_vacuum_cost_limit too high, the autovacuum process might consume too many resources and slow down other queries. If you set it too low, the autovacuum process might not reclaim enough space, which causes the table to become larger over time. If you want to override the default please specify a value or else hit enter"),
				),
				validation: validateIntRangeAllowEmpty(-1, 10000),
				setFunc:    fieldSetFunctionDefault("autovacuum_vacuum_cost_limit", "-1"),
				skipFunc:   skipIfSetFieldFunction("autovacuum_vacuum_cost_limit"),
			},
			{
				label:       "Specify autovacuum_vacuum_cost_delay",
				helpMessage: "Value in milliseconds (ms) Default: 2 ms",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - As soon as autovacuum_vacuum_cost_limit is hit autovacuum job is paused for autovacuum_vacuum_cost_delay. If you want to override the default please specify a value or else hit enter. NOTE - It’s best to stick with the default value unless you have some vacuuming issues"),
				),
				validation: validateIntRangeAllowEmpty(-1, 100),
				setFunc:    fieldSetFunctionDefault("autovacuum_vacuum_cost_delay", "2"),
				skipFunc:   skipIfSetFieldFunction("autovacuum_vacuum_cost_delay"),
			},
			{
				label:       "Specify autovacuum_max_workers",
				helpMessage: "Default: 3",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - If you have hundreds and thousands of tables it is better to increase this to a bigger number .. But make sure you have lot of cores to support the increase .If you want to override the default please specify a value or else hit enter. NOTE - It’s best to stick with the default value unless you have some vacuuming issues"),
				),
				validation: validateIntRangeAllowEmpty(1, 262143),
				setFunc:    fieldSetFunctionDefault("autovacuum_max_workers", "3"),
				skipFunc:   skipIfSetFieldFunction("autovacuum_max_workers"),
			},
			{
				label:       "Recommended JIT setting: 'off' for OLTP/web apps, 'on' for data warehouses. Benchmark critical apps to find the best setting.",
				helpMessage: "Default: 'off'",
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("jit", "off"),
				skipFunc: EmptySkipFunc,
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
			{
				heading:     "SECURITY SETTINGS",
				label:       "For enhanced security, we recommend the following settings.\n\t• To proceed with these settings, press Y.\n\t• To customize them, press N, and we'll guide you through the process step by step.",
				helpMessage: "y/N",
				validation:  validateBool,
				extraMessage: fmt.Sprintf(
					"\n\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n%s",
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("log_connections"), text.FgHiGreen.Sprint("'on'")),
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("log_disconnections"), text.FgHiGreen.Sprint("'on'")),
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("log_statement"), text.FgHiGreen.Sprint("'all'")),
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("ssl"), text.FgHiGreen.Sprint("'on'")),
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("log_line_prefix"), text.FgHiGreen.Sprint("'%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h'")), //nolint:govet
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("logging_collector"), text.FgHiGreen.Sprint("'on'")),
					fmt.Sprintf("%-30s = %s", text.FgHiCyan.Sprint("log_destination"), text.FgHiGreen.Sprint("'stderr'")),
					text.FgHiGreen.Sprint("<Hit ENTER to use recommended values>"),
				),
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "no" {
						return nil
					}

					// Set defaults
					m["log_connections"] = "on"
					m["log_disconnections"] = "on"
					m["log_statement"] = "all"
					m["ssl"] = "on"
					m["log_line_prefix"] = "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h"
					m["logging_collector"] = "on"
					m["log_destination"] = "stderr"
					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify log_connections",
				helpMessage:  "on|off. Default: on",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("log_connections", "on"),
				skipFunc: skipIfSetFieldFunction("log_connections"),
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify log_disconnections",
				helpMessage:  "on|off. Default: on",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("log_disconnections", "on"),
				skipFunc: skipIfSetFieldFunction("log_disconnections"),
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify log_statement",
				helpMessage:  "none|ddl|mod|all. Default: all",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:none|ddl|mod|all)?$`),
					"input data is not valid. Enter one of the [none, ddl, mod, all]",
				),
				setFunc:  fieldSetFunctionDefault("log_statement", "all"),
				skipFunc: skipIfSetFieldFunction("log_statement"),
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify ssl",
				helpMessage:  "on|off. Default: on",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("ssl", "on"),
				skipFunc: skipIfSetFieldFunction("ssl"),
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify log_line_prefix",
				helpMessage:  "e.g : %m [%p], Default: '%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h'",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation:   EmptyValidationfunc,
				setFunc:      fieldSetFunctionDefault("log_line_prefix", "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h"),
				skipFunc:     skipIfSetFieldFunction("log_line_prefix"),
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify logging_collector",
				helpMessage:  "on|off. Default: on",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("logging_collector", "on"),
				skipFunc: skipIfSetFieldFunction("logging_collector"),
			},
			{
				heading:      "SECURITY SETTINGS",
				label:        "Specify log_destination",
				helpMessage:  "stderr|csv|syslog , Default: stderr",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:stderr|csv|syslog)?$`),
					"input data is not valid. Enter one of the [stderr, csv, syslog]",
				),
				setFunc:  fieldSetFunctionDefault("log_destination", "stderr"),
				skipFunc: skipIfSetFieldFunction("log_destination"),
			},
			{
				heading:     "LOGGING SETTINGS",
				label:       "Logging settings are crucial for monitoring and troubleshooting.\n\t• To proceed with the recommended settings, press Y.\n\t• To customize them, press N, and we'll guide you through the process step by step.",
				helpMessage: "y/N",
				validation:  validateBool,
				extraMessage: fmt.Sprintf(
					"\n\n%s\n%s\n%s\n%s\n%s\n\n%s",
					fmt.Sprintf("%-38s = %s", text.FgHiCyan.Sprint("log_checkpoints"), text.FgHiGreen.Sprint("'on'")),
					fmt.Sprintf("%-38s = %s", text.FgHiCyan.Sprint("log_lock_waits"), text.FgHiGreen.Sprint("'on'")),
					fmt.Sprintf("%-38s = %s", text.FgHiCyan.Sprint("log_temp_files"), text.FgHiGreen.Sprint("'1KB'")),
					fmt.Sprintf("%-38s = %s", text.FgHiCyan.Sprint("log_autovacuum_min_duration"), text.FgHiGreen.Sprint("'600000(ms)'")),
					fmt.Sprintf("%-38s = %s", text.FgHiCyan.Sprint("log_min_duration_statement"), text.FgHiGreen.Sprint("'1s'")),
					text.FgHiGreen.Sprint("<Hit ENTER to use recommended values>"),
				),
				setFunc: func(m map[string]string, val string) error {
					if simplifyBoolVal(val) == "no" {
						return nil
					}

					// Set defaults
					m["log_checkpoints"] = "on"
					m["log_lock_waits"] = "on"
					m["log_temp_files"] = "1"
					m["log_autovacuum_min_duration"] = "600000"
					m["log_min_duration_statement"] = "1000"
					return nil
				},
				skipFunc: EmptySkipFunc,
			},
			{
				heading:      "LOGGING SETTINGS",
				label:        "Specify log_checkpoints",
				helpMessage:  "on|off. Default: on",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("log_checkpoints", "on"),
				skipFunc: skipIfSetFieldFunction("log_checkpoints"),
			},
			{
				heading:      "LOGGING SETTINGS",
				label:        "Specify log_lock_waits",
				helpMessage:  "on|off. Default: on",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`(?i)^(?:on|off)?$`),
					"input data is not valid. Enter on/off",
				),
				setFunc:  fieldSetFunctionDefault("log_lock_waits", "on"),
				skipFunc: skipIfSetFieldFunction("log_lock_waits"),
			},
			{
				heading:      "LOGGING SETTINGS",
				label:        "Specify log_temp_files",
				helpMessage:  "Enter a value in KB, MB or GB, Default: 1KB",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation: validateRegExp(
					regexp.MustCompile(`^(?:\s*[1-9]\d*\s*(?:KB|MB|GB|K|M|G|Kb|Mb|Gb|kB|mB|gB|lb|mb|gb))?$`),
					"input data is not a valid file size",
				),
				setFunc:  fieldSetSizeInKB("log_temp_files", "1"),
				skipFunc: skipIfSetFieldFunction("log_temp_files"),
			},
			{
				heading:      "LOGGING SETTINGS",
				label:        "Specify log_autovacuum_min_duration",
				helpMessage:  "Value in milliseconds (ms). Default: 600000(ms)",
				extraMessage: text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
				validation:   validateIntRangeAllowEmpty(1, 2147483647),
				setFunc:      fieldSetFunctionDefault("log_autovacuum_min_duration", "600000"),
				skipFunc:     skipIfSetFieldFunction("log_autovacuum_min_duration"),
			},
			{
				heading:     "LOGGING SETTINGS",
				label:       "Specify log_min_duration_statement",
				helpMessage: "Value in milliseconds (ms). Default: 1s",
				extraMessage: fmt.Sprintf("%s\n\n%s",
					text.FgHiGreen.Sprint("<Hit ENTER to use default value>"),
					text.FgHiYellow.Sprint("NOTE - log_min_duration_statement - Logs the duration of any completed statement that takes at least the specified amount of time to execute. For example, if set to 250ms, all SQL statements running for 250ms or longer will be logged. The recommended value is typically 1s or 2s, depending on your specific use case"),
				),
				validation: validateIntRangeAllowEmpty(1, 2147483647),
				setFunc:    fieldSetFunctionDefault("log_min_duration_statement", "1000"),
				skipFunc:   skipIfSetFieldFunction("log_min_duration_statement"),
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
	reader := bufio.NewReader(os.Stdin)
	for _, n := range p.nodes {
		skip, err := n.skipFunc(p.data)
		if err != nil {
			return err
		}

		if skip {
			continue
		}

		fmt.Print("\033[H\033[2J") // Clear terminal

		// Get the terminal width dynamically
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			width = 80 // Fallback to 80 if unable to get terminal width
		}

		termProfile := termenv.ColorProfile()

		// Print center-aligned heading if its length > 0
		if len(n.heading) > 0 {
			heading := termenv.String(n.heading).Bold().Foreground(termProfile.Color("#FFA500")).String() // Orange and bold
			padding := (width - len(stripAnsiCodes(n.heading))) / 2
			if padding < 0 {
				padding = 0 // Prevent negative padding
			}
			fmt.Printf("%s%s\n\n", strings.Repeat(" ", padding), heading)
		}
		fmt.Printf("> %s: ", n.label)
		if len(n.helpMessage) > 0 {
			fmt.Printf("[%s] ", text.FgHiCyan.Sprint(n.helpMessage))
		}
		if len(n.extraMessage) > 0 {
			fmt.Printf("%s ", n.extraMessage)
		}
		if len(n.helpMessage) > 0 || len(n.extraMessage) > 0 {
			fmt.Print(": ")
		}

		var userInput string
		i := 0
		for ; i < 3; i++ {
			userInput = ""
			if len(n.options) == 0 {
				userInput, _ = reader.ReadString('\n')
				userInput = strings.TrimSpace(userInput)
			} else {
				fmt.Println()
				for i, v := range n.options {
					fmt.Println("\t" + text.Bold.Sprint(i+1) + ". " + v)
				}

				// wait for user input
				fmt.Print("Select one from the list :")

				userInput, _ = reader.ReadString('\n')
				userInput = strings.TrimSpace(userInput)

				if userInput == "" {
					fmt.Print(text.FgRed.Sprintf("You have not selected any option. Please enter an integer to select."))
					continue
				}

				val, err := strconv.Atoi(userInput)
				if err != nil {
					fmt.Print(text.FgRed.Sprintf("Error: '%s' is not a valid integer.", userInput) + " Please retry.\n")
					continue
				}

				if val > len(n.options) || val <= 0 {
					// invalid value
					fmt.Println(text.FgRed.Sprint("invalid option selected. please retry"))
					continue
				}
				userInput = n.options[val-1]
			}

			err := n.validation(p.data, userInput)
			if err == nil {
				break
			}

			fmt.Printf(
				"Invalid input detected. Error: %v\nTry again (available retries: %d) :",
				text.FgRed.Sprint(err),
				2-i,
			)
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

func (p *processor) GenerateConfigFile(configPath string) error {
	configString := ConfigGenerator(p.GetData())
	err := WriteToFile(configString, configPath)
	if err != nil {
		fmt.Printf("\n%s Error: %v ❌\n", text.FgRed.Sprintf("Error:"), err)
		return err
	}
	absolutePath, _ := filepath.Abs(configPath)
	fmt.Printf("\n%s Config file has been generated at %s ✅\n", text.FgGreen.Sprintf("Success:"), absolutePath)

	return nil
}

// stripAnsiCodes removes ANSI escape codes to correctly calculate string length
func stripAnsiCodes(input string) string {
	ansiEscape := "\033\\[[0-9;]*m"
	return strings.ReplaceAll(strings.ReplaceAll(input, ansiEscape, ""), "\033[0m", "")
}
