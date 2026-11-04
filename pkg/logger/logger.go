package logger

import (
	"fmt"
	stdlog "log"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var logFileName string
var fileLogger zerolog.Logger

func FileLogger() *zerolog.Logger {
	return &fileLogger
}

func GetLogFileName() string {
	return logFileName
}

func SetupLogger() {
	// create log file
	f, err := createLogFile()
	if err != nil {
		fmt.Println("Error creating log file: ", err, " will be writing logs to stdout")
		f = os.Stdout
	}

	// Initialize file logger
	fileWriter := zerolog.ConsoleWriter{Out: f, TimeFormat: time.RFC1123Z, NoColor: true}
	fileLogger = zerolog.New(fileWriter).With().Timestamp().Logger()
	fileLogger.Level(zerolog.InfoLevel)

	// Initialize terminal logger as default
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC1123Z}
	log.Logger = zerolog.New(consoleWriter).With().Timestamp().Caller().Logger()
	log.Logger.Level(zerolog.TraceLevel)

}

// OutputLogDir is where terminal output goes with --log-to-file.
const OutputLogDir = "/var/log/klouddbshield"

// RedirectOutputToFile sends everything this process writes to stdout/stderr
// into OutputLogDir/ciscollector_output_<timestamp>.log and returns that path.
// Loggers must be (re)created after this call, since they hold the writer
// they were built with.
func RedirectOutputToFile() (string, error) {
	dir, err := filepath.Abs(OutputLogDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	name := filepath.Join(dir, "ciscollector_output_"+time.Now().Format("20060102_150405")+".log")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", err
	}

	os.Stdout = f
	os.Stderr = f
	stdlog.SetOutput(f)
	return name, nil
}

func createLogFile() (*os.File, error) {
	// create log file directory if not exists in user home directory
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(path.Join(userHomeDir, ".klouddb"), 0755)
	if err != nil {
		return nil, err
	}

	logFileName = path.Join(userHomeDir, ".klouddb", "logparser_"+time.Now().Format("20060102_150405_")+".log")

	return os.Create(logFileName)
}
