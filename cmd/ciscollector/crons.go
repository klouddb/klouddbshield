package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/pkg/config"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/cron"
	"github.com/klouddb/klouddbshield/pkg/email"
	"github.com/klouddb/klouddbshield/pkg/mainserverclient"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/reportstore"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/rs/zerolog/log"
)

type Runner interface {
	cronProcess(ctx context.Context) error
}

func getProcessorsForCron(schedule string, commnd *config.Command, htmlHelperMap htmlreport.HtmlReportHelperMap, fileData map[string]interface{}, shield *config.Config) ([]Runner, error) {
	switch commnd.Name {
	case cons.RootCMD_All:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			htmlHelper := htmlHelperMap.Get(p.HtmlReportName())

			out = append(out, newPostgresRunnerFromConfig(p, fileData,
				utils.NewDummyContainsAllSet[string](), htmlHelper, "json"))
			out = append(out, newHBARunnerFromConfig(p, fileData, htmlHelper, "json"))
			out = append(out, newSslAuditor(p, fileData, htmlHelper, "json"))

			out = append(out, newPwnedUserRunner(p, true, fileData, htmlHelper, "json"))
		}

		logPaser, err := getLogParserCron(schedule, commnd, htmlHelperMap, fileData)
		if err != nil {
			return nil, err
		}

		out = append(out, logPaser...)

		if shield != nil {
			for _, p := range commnd.Postgres {
				piiCfg, err := shield.BuildPiiScannerConfig(p, config.PiiScannerOverrides{})
				if err != nil {
					return nil, fmt.Errorf("piiscanner: %w", err)
				}
				htmlHelper := htmlHelperMap.Get(p.HtmlReportName())
				out = append(out, newPiiDbScanner(p, piiCfg, htmlHelper, shield))
			}
			if shield.BackupCompliance.Enabled {
				for _, p := range commnd.Postgres {
					out = append(out, newBackupComplianceRunner(p, shield))
				}
			}
		}

		return out, nil
	case cons.RootCMD_AllCore:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}
		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			htmlHelper := htmlHelperMap.Get(p.HtmlReportName())
			out = append(out, newPostgresRunnerFromConfig(p, fileData,
				utils.NewDummyContainsAllSet[string](), htmlHelper, "json"))
			out = append(out, newHBARunnerFromConfig(p, fileData, htmlHelper, "json"))
			out = append(out, newSslAuditor(p, fileData, htmlHelper, "json"))
			out = append(out, newPwnedUserRunner(p, true, fileData, htmlHelper, "json"))
		}
		return out, nil
	case cons.RootCMD_PostgresCIS:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newPostgresRunnerFromConfig(p, fileData,
				utils.NewDummyContainsAllSet[string](), htmlHelperMap.Get(p.HtmlReportName()), "json"))
		}

		return out, nil

	case cons.RootCMD_HBAScanner:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newHBARunnerFromConfig(p, fileData, htmlHelperMap.Get(p.HtmlReportName()), "json"))
		}

		return out, nil

	case cons.RootCMD_SSLCheck:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newSslAuditor(p, fileData, htmlHelperMap.Get(p.HtmlReportName()), "json"))
		}

		return out, nil

	case cons.PasswordManager_CommonUsers:
		// check other 3 options
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}

		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newPwnedUserRunner(p, false, fileData, htmlHelperMap.Get(p.HtmlReportName()), "json"))
		}
		return out, nil

	case cons.RootCMD_AWSRDS:
		return []Runner{newRDSRunner("json", fileData, "RDS Report")}, nil
	case cons.RootCMD_AWSAurora:
		return []Runner{newRDSRunner("json", fileData, "Aurora Report")}, nil

	case cons.RootCMD_MySQL:
		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.MySQL {
			out = append(out, newMySqlRunner(p, fileData, htmlHelperMap.Get(p.HtmlReportName()), "json"))
		}
		return out, nil

	case cons.LogParserCMD_UniqueIPs, cons.LogParserCMD_InactiveUser,
		cons.LogParserCMD_HBAUnusedLines, cons.LogParserCMD_PasswordLeakScanner:
		return getLogParserCron(schedule, commnd, htmlHelperMap, fileData)

	case cons.RootCMD_GucDrift:
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}
		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newGucSettingsRunner(p))
		}
		return out, nil

	case cons.RootCMD_PiiScanner:
		if shield == nil {
			return nil, fmt.Errorf("shield config required for pii scanner")
		}
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_PostgresConfig_Missing)
		}
		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			piiCfg, err := shield.BuildPiiScannerConfig(p, config.PiiScannerOverrides{})
			if err != nil {
				return nil, fmt.Errorf("piiscanner: %w", err)
			}
			htmlHelper := htmlHelperMap.Get(p.HtmlReportName())
			out = append(out, newPiiDbScanner(p, piiCfg, htmlHelper, shield))
		}
		return out, nil

	case cons.RootCMD_BackupCompliance:
		if shield == nil {
			return nil, fmt.Errorf(cons.Err_BackupCompliance_ShieldRequired)
		}
		if len(commnd.Postgres) == 0 {
			return nil, fmt.Errorf(cons.Err_BackupCompliance_PostgresRequired)
		}
		out := make([]Runner, 0, len(commnd.Postgres))
		for _, p := range commnd.Postgres {
			out = append(out, newBackupComplianceRunner(p, shield))
		}
		return out, nil

	default:
		return nil, fmt.Errorf("invalid command %s", commnd.Name)
	}
}

func getLogParserCron(schedule string, command *config.Command, htmlHelperMap htmlreport.HtmlReportHelperMap, fileData map[string]interface{}) ([]Runner, error) {
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

		u := newLogParserRunnerFromConfig(p, logParserConfig, false, fileData, htmlHelperMap.Get(p.HtmlReportName()), "json")
		out = append(out, u)
	}

	return out, nil
}

type cronHelper struct {
	cnf *config.Config
	c   *cron.Cron
	ctx context.Context

	mu        sync.Mutex
	entryByID map[string]cron.EntryID
	hashByID  map[string]string

	reportDirPath string
	emailHelper   *email.EmailHelper

	push *cronPushState
}

func NewCronHelper(ctx context.Context, cnf *config.Config) *cronHelper {
	return &cronHelper{
		cnf:       cnf,
		c:         cron.New(),
		ctx:       ctx,
		entryByID: map[string]cron.EntryID{},
		hashByID:  map[string]string{},
	}
}

func (c *cronHelper) SetupCron() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory: ", err, ". Reports will be stored in tmp directory.")
		homeDir = os.TempDir()
	}
	c.reportDirPath = path.Join(homeDir, ".klouddb")

	// create klouddbshield_report directory in home directory if not exists
	if _, err := os.Stat(c.reportDirPath); os.IsNotExist(err) {
		err := os.Mkdir(c.reportDirPath, 0755)
		if err != nil {
			return err
		}
	}

	if c.cnf.Email != nil {
		c.emailHelper = email.NewEmailHelper(c.cnf.Email.Host, c.cnf.Email.Port, c.cnf.Email.Username, c.cnf.Email.Password)
		err := c.emailHelper.VerifyConfig()
		if err != nil {
			return err
		}
	}
	if err := c.reconcileSchedules(); err != nil {
		return err
	}
	if c.cnf.MainServer.Enabled {
		c.startMainServerPush()
	}
	return nil
}

func (c *cronHelper) collectorCommandMap() (map[string][]config.Command, error) {
	return c.cnf.BuildCollectorScheduleMap()
}

func commandMapSignature(commands []config.Command) string {
	var b strings.Builder
	for _, cmd := range commands {
		b.WriteString(cmd.Name)
		b.WriteString("|")
		for _, pg := range cmd.Postgres {
			if pg == nil {
				continue
			}
			b.WriteString(pg.Host)
			b.WriteString(":")
			b.WriteString(pg.Port)
			b.WriteString("/")
			b.WriteString(pg.DBName)
			b.WriteString(";")
		}
		if cmd.LogParser != nil {
			b.WriteString(cmd.LogParser.Prefix)
			b.WriteString("|")
			b.WriteString(cmd.LogParser.LogFile)
			b.WriteString("|")
			b.WriteString(cmd.LogParser.HbaConfFile)
		}
		b.WriteString("#")
	}
	return b.String()
}

func sortedKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprintf("%v", keys[i]) < fmt.Sprintf("%v", keys[j]) })
	return keys
}

type cronTargetPush struct {
	pg       *postgresdb.Postgres
	fileData map[string]interface{}
	features []string
	runErr   string
}

func (c *cronHelper) scheduleRunner(schedule string, commands []config.Command) func() {
	sched := schedule
	cmds := append([]config.Command(nil), commands...)
	return func() {
		ctx := context.Background()
		htmlHelperMap := htmlreport.NewHtmlReportHelperMap()
		targetAcc := map[string]*cronTargetPush{}
		var cronFeatures []string
		runStarted := time.Now().UTC()
		var runErr string
		c.markCronRunning(true)
		defer c.markCronRunning(false)

		defer func() {
			client := c.pushClient()
			if client != nil {
				for _, tid := range sortedKeys(targetAcc) {
					st := targetAcc[tid]
					if st == nil || len(st.fileData) == 0 {
						continue
					}
					_, _ = pushMainServerTickResults(
						c.cnf, client, st.fileData, runStarted, time.Now().UTC(),
						st.pg, "cron", st.features, st.runErr,
					)
				}
				c.pushCronRunFinishWithClient(client, runStarted, cronFeatures, runErr)
			}
		}()

		if client := c.pushClient(); client != nil {
			_ = client.PushActivity(ctx, mainserverclient.ActivityPayload{
				Kind:    "cron_tick",
				Message: "cron tick started: " + sched,
				Level:   "info",
			})
		}

		defer func() {
			allFiles := []string{}
			for k, v := range htmlHelperMap {
				filename := path.Join(c.reportDirPath, "klouddbshield_report_"+k+".html")
				filePath, err := v.RenderInfile(filename, 0600)
				if err != nil {
					log.Error().Err(err).Msg("Unable to generate klouddbshield_report.html file: " + err.Error())
					return
				}

				if filePath != "" {
					allFiles = append(allFiles, filePath)
				}
			}

			if len(allFiles) == 0 || c.emailHelper == nil {
				return
			}
			err := c.emailHelper.Send("KloudDBShield Report", "Klouddb shield email report", allFiles)
			if err != nil {
				log.Error().Err(err).Msg("Unable to send email: " + err.Error())
			}
		}()
		for _, commnd := range cmds {
			fmt.Println("Running command: ", commnd.Name)
			cronFeatures = append(cronFeatures, commnd.Name)
			if len(commnd.Postgres) == 0 {
				err := fmt.Errorf(cons.Err_PostgresConfig_Missing)
				fmt.Printf("Error: %v\n", err)
				if runErr == "" {
					runErr = err.Error()
				}
				c.recordCronRunError(err.Error())
				continue
			}

			for _, pg := range commnd.Postgres {
				pgCmd := commnd
				pgCmd.Postgres = []*postgresdb.Postgres{pg}
				tid := reportstore.TargetID(pg)
				st := targetAcc[tid]
				if st == nil {
					st = &cronTargetPush{
						pg:       pg,
						fileData: map[string]interface{}{},
					}
					targetAcc[tid] = st
				}
				st.features = append(st.features, commnd.Name)

				processors, err := getProcessorsForCron(sched, &pgCmd, htmlHelperMap, st.fileData, c.cnf)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					if runErr == "" {
						runErr = err.Error()
					}
					if st.runErr == "" {
						st.runErr = err.Error()
					}
					c.recordCronRunError(err.Error())
					continue
				}

				for _, p := range processors {
					if err := p.cronProcess(ctx); err != nil {
						fmt.Printf("Error: %v\n", err)
						if runErr == "" {
							runErr = err.Error()
						}
						if st.runErr == "" {
							st.runErr = err.Error()
						}
						c.recordCronRunError(err.Error())
						if client := c.pushClient(); client != nil {
							_ = client.PushLog(ctx, mainserverclient.LogPayload{
								Level:   "error",
								Message: err.Error(),
							})
						}
					}
				}
			}
		}
	}
}

func (c *cronHelper) buildCommandMap() (map[string][]config.Command, map[string]string, error) {
	merged, err := c.collectorCommandMap()
	if err != nil {
		return nil, nil, err
	}
	hashes := map[string]string{}
	for sched, commands := range merged {
		hashes[sched] = commandMapSignature(commands)
	}
	c.setScheduledJobCount(len(merged))
	return merged, hashes, nil
}

func (c *cronHelper) reconcileSchedules() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	commandMap, hashes, err := c.buildCommandMap()
	if err != nil {
		return err
	}
	// Remove deleted schedules.
	for sched, entryID := range c.entryByID {
		if _, ok := commandMap[sched]; ok {
			continue
		}
		c.c.Remove(entryID)
		delete(c.entryByID, sched)
		delete(c.hashByID, sched)
	}
	// Add/update changed schedules.
	for _, sched := range sortedKeys(commandMap) {
		cmds := commandMap[sched]
		newHash := hashes[sched]
		oldHash := c.hashByID[sched]
		if oldHash == newHash {
			continue
		}
		if entryID, ok := c.entryByID[sched]; ok {
			c.c.Remove(entryID)
		}
		entryID, err := c.c.AddFuncWithID(sched, c.scheduleRunner(sched, cmds))
		if err != nil {
			return err
		}
		c.entryByID[sched] = entryID
		c.hashByID[sched] = newHash
	}
	return nil
}

func (c *cronHelper) Run(cancel context.CancelFunc) {
	fmt.Println("starting crons")
	c.mu.Lock()
	n := len(c.entryByID)
	schedules := sortedKeys(c.entryByID)
	c.mu.Unlock()
	if n == 0 {
		fmt.Println("WARNING: no cron jobs registered — check [collector] schedule and scan_commands in kshieldconfig.toml")
	} else {
		fmt.Printf("registered %d cron schedule(s); waiting for next run time:\n", n)
		for _, sched := range schedules {
			fmt.Printf("  - %s\n", sched)
		}
		fmt.Println("(robfig cron: minute hour day month weekday — e.g. \"17 17 * * *\" = daily at 17:17)")
	}

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
