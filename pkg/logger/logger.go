package logger

import (
	"fmt"
	"os"
	"path"
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
