package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/cron"
	"github.com/klouddb/klouddbshield/pkg/email"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/rs/zerolog/log"
)

type Runner interface {
	cronProcess(ctx context.Context) error
}

func getProcessorsForCron(schedule string, commnd *config.Command, htmlHelperMap htmlreport.HtmlReportHelperMap) ([]Runner, error) {
	switch commnd.Name {
	case cons.RootCMD_All:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			htmlHelper := htmlHelperMap.Get(p.HtmlReportName())

			out = append(out, newPostgresRunnerFromConfig(p, &strings.Builder{},
				utils.NewDummyContainsAllSet[string](), htmlHelper))
			out = append(out, newHBARunnerFromConfig(p, &strings.Builder{}, htmlHelper))

			out = append(out, newPwnedUserRunner(p, true, &strings.Builder{}, htmlHelper))
		}

		logPaser, err := getLogParserCron(schedule, commnd, htmlHelperMap)
		if err != nil {
			return nil, err
		}

		out = append(out, logPaser...)

		return out, nil
	case cons.RootCMD_PostgresCIS:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newPostgresRunnerFromConfig(p, &strings.Builder{},
				utils.NewDummyContainsAllSet[string](), htmlHelperMap.Get(p.HtmlReportName())))
		}

		return out, nil

	case cons.RootCMD_HBAScanner:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newHBARunnerFromConfig(p, &strings.Builder{}, htmlHelperMap.Get(p.HtmlReportName())))
		}

		return out, nil

	case cons.PasswordManager_CommonUsers:
		// check other 3 options
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newPwnedUserRunner(p, false, &strings.Builder{}, htmlHelperMap.Get(p.HtmlReportName())))
		}
		return out, nil

	case cons.RootCMD_AWSRDS, cons.RootCMD_AWSAurora:
		return []Runner{newRDSRunner(&strings.Builder{})}, nil

	case cons.RootCMD_MySQL:
		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.MySQL {
			out = append(out, newMySqlRunner(p, &strings.Builder{}, htmlHelperMap.Get(p.HtmlReportName())))
		}
		return out, nil

	case cons.LogParserCMD_UniqueIPs, cons.LogParserCMD_InactiveUsr,
		cons.LogParserCMD_HBAUnusedLines, cons.LogParserCMD_PasswordLeakScanner:
		return getLogParserCron(schedule, commnd, htmlHelperMap)

	default:
		return nil, fmt.Errorf("invalid command %s", commnd.Name)
	}
}

func getLogParserCron(schedule string, command *config.Command, htmlHelperMap htmlreport.HtmlReportHelperMap) ([]Runner, error) {
	if len(command.Postgres) == 0 {
		return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}

	startTime, err := cron.GetPreviousExecutionTime(schedule)
	if err != nil {
		return nil, fmt.Errorf("error getting previous execution time: %v", err)
	}

	out := make([]Runner, 0, len(command.Postgres))
	for _, p := range command.Postgres {
		logParserConfig, err := config.NewLogParser(command.Name, "", "",
			command.LogParser.Prefix, command.LogParser.LogFile, command.LogParser.HbaConfFile)
		if err != nil {
			return nil, fmt.Errorf("error creating logparser config: %v", err)
		}

		logParserConfig.Begin = startTime
		logParserConfig.End = time.Now()

		u := newLogParserRunnerFromConfig(p, logParserConfig, false, &strings.Builder{}, htmlHelperMap.Get(p.HtmlReportName()))
		out = append(out, u)
	}

	return out, nil
}

type cronHelper struct {
	cnf *config.Config
	c   *cron.Cron
	ctx context.Context
}

func NewCronHelper(ctx context.Context, cnf *config.Config) *cronHelper {
	return &cronHelper{
		cnf: cnf,
		c:   cron.New(),
		ctx: ctx,
	}
}

func (c *cronHelper) SetupCron() error {
	// b, _ := json.Marshal(c.cnf)
	// fmt.Println("Config: ", string(b))
	// return nil

	var emailHelper *email.EmailHelper
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory: ", err, ". Reports will be stored in tmp directory.")
		homeDir = os.TempDir()
	}

	reportDirPath := path.Join(homeDir, ".klouddb")

	// create klouddbshield_report directory in home directory if not exists
	if _, err := os.Stat(reportDirPath); os.IsNotExist(err) {
		err := os.Mkdir(reportDirPath, 0755)
		if err != nil {
			return err
		}
	}

	if c.cnf.Email != nil {
		emailHelper = email.NewEmailHelper(c.cnf.Email.Host, c.cnf.Email.Port, c.cnf.Email.Username, c.cnf.Email.Password)
		err := emailHelper.VerifyConfig()
		if err != nil {
			return err
		}
	} else {
		fmt.Println("> Email configuration not found in config file. For report you can refer your home directory. [" + homeDir + "]")
	}

	commandMap := map[string][]config.Command{}

	for _, v := range c.cnf.Crons {
		// if v.Schedule freequence is less than 24 hours, then return error
		ok, err := cron.IsLessThan24Hours(v.Schedule)
		if err != nil {
			return err
		}

		if !ok {
			return fmt.Errorf("schedule frequency should be less than 24 hours")
		}

		commandMap[v.Schedule] = append(commandMap[v.Schedule], v.Commands...)
	}

	for schedule, commands := range commandMap {
		err := c.c.AddFunc(schedule, func() {
			ctx := context.Background()
			htmlHelperMap := htmlreport.NewHtmlReportHelperMap()

			defer func() {
				allFiles := []string{}
				for k, v := range htmlHelperMap {
					filename := path.Join(reportDirPath, "klouddbshield_report_"+k+".html")
					filePath, err := v.RenderInfile(filename, 0600)
					if err != nil {
						log.Error().Err(err).Msg("Unable to generate klouddbshield_report.html file: " + err.Error())
						return
					}

					if filePath != "" {
						allFiles = append(allFiles, filePath)
					}
				}

				if len(allFiles) == 0 {
					return
				}

				if emailHelper == nil {
					log.Info().Msg("Email configuration not found in config file. For report you can refer your home directory. [" + homeDir + "]")
				}

				err := emailHelper.Send("prince.soamedia@gmail.com", "KloudDBShield Report", "Klouddb shield email report", allFiles)
				if err != nil {
					log.Error().Err(err).Msg("Unable to send email: " + err.Error())
				}
			}()
			for _, commnd := range commands {
				fmt.Println("Running command: ", commnd.Name)
				processors, err := getProcessorsForCron(schedule, &commnd, htmlHelperMap)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}

				for _, p := range processors {
					if err := p.cronProcess(ctx); err != nil {
						fmt.Printf("Error: %v\n", err)
					}
				}
			}
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *cronHelper) Run(cancel context.CancelFunc) {
	fmt.Println("starting crons")

	// Start the cron
	c.c.Start()

	// Handle interrupts
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	<-signals

	// Log the interrupt signal with stack trace
	log.Info().Msg("Received an interrupt signal, shutting down")

	// Cancel the program context
	cancel()

	// Extract cron done context
	ctx := c.c.Stop()
	if err := ctx.Err(); err != nil {
		log.Error().Err(err).Msg("Stopping all jobs")
	}

	log.Info().Msg("Stopping all jobs")
}
