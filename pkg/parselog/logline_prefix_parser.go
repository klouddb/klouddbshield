package parselog

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/utils"
)

/*

it will parse multiple kind of log lines
prefix type =>
	regex string
	userindex int
	hostindex int
	databaseindex int
	timeindex int
	timeformat string

methods =>
	GetUser() string
	GetHost() string
	GetDatabase() string
	GetTime() time.Time

will create one base parser
after setting different values in base parser we will create multiple parser based on logline prefix
*/

// //////////////////////////////// parsed data /////////////////////////////////
type ParsedData interface {
	GetUser() (string, error)
	GetHost() (string, error)
	GetDatabase() (string, error)
	GetLogLevel() string
	GetDescription() string
	GetTime() time.Time
}

type parsingIndex struct {
	// index of user, host, database, time in regex
	timeIndex     *int
	userIndex     *int
	hostIndex     *int
	databaseIndex *int
}

type parsedData struct {

	// time related details
	levelIndex int

	parsingIndex

	// parsed data
	parsedData utils.StringSlice
	parsedTime time.Time
}

// NewParsedData will return parsedData from baseParser
func NewParsedData(baseParser *baseParser) *parsedData {
	return &parsedData{
		parsingIndex: baseParser.parsingIndex,
		levelIndex:   baseParser.levelIndex,
	}
}

// getter methods
// GetUser will return user from parsed data
func (b *parsedData) GetUser() (string, error) {
	if b.userIndex == nil {
		return "", fmt.Errorf("user is not set in this parser")
	}

	u := b.parsedData.Get(*b.userIndex)
	if u == "" || u == "[unknown]" {
		return "", fmt.Errorf("invalid value for user")
	}

	return u, nil
}

// GetHost will return host from parsed data
func (b *parsedData) GetHost() (string, error) {
	if b.hostIndex == nil {
		return "", fmt.Errorf("host is not set in this parser")
	}

	h := b.parsedData.Get(*b.hostIndex)
	if h == "" || h == "[unknown]" {
		return "", fmt.Errorf("invalid value for host")
	}

	// to handle host with port
	if strings.Contains(h, "(") {
		h = strings.Split(h, "(")[0]
	}

	return h, nil
}

// GetDatabase will return database from parsed data
func (b *parsedData) GetDatabase() (string, error) {
	if b.databaseIndex == nil {
		return "", fmt.Errorf("database is not set in this parser")
	}

	d := b.parsedData.Get(*b.databaseIndex)
	if d == "" || d == "[unknown]" {
		return "", fmt.Errorf("invalid value for database")
	}

	return d, nil
}

func (b *parsedData) GetLogLevel() string {
	return b.parsedData.Get(b.levelIndex)
}

func (b *parsedData) GetDescription() string {
	return b.parsedData[b.levelIndex+1]
}

// GetTime will return time from parsed data
func (b *parsedData) GetTime() time.Time {
	return b.parsedTime
}

// setter methods
// SetParsedData will set parsed data
func (b *parsedData) SetParsedData(parsedData utils.StringSlice) *parsedData {
	b.parsedData = parsedData
	return b
}

// SetParsedTime will set parsed time
func (b *parsedData) SetParsedTime(parsedTime time.Time) *parsedData {
	b.parsedTime = parsedTime
	return b
}

// BaseParser is an interface for parsing log lines.
type BaseParser interface {
	Parse(string) (ParsedData, error)
}

type baseParser struct {
	// regex related details
	regex *regexp.Regexp

	timeFormat    string
	timeFormatAlt string

	// index of user, host, database, time in regex
	parsingIndex

	// time related details
	levelIndex int
}

func NewBaseParser(regex *regexp.Regexp, timeIndex, logLevelIndex int) *baseParser {
	return &baseParser{
		regex: regex,
		parsingIndex: parsingIndex{
			timeIndex: &timeIndex,
		},
		levelIndex: logLevelIndex,

		timeFormat:    "2006-01-02 15:04:05 -0700",
		timeFormatAlt: "2006-01-02 15:04:05 MST",
	}
}

func NewBaseParserFromRegex(regex *regexp.Regexp) *baseParser {
	return &baseParser{
		regex: regex,

		timeFormat:    "2006-01-02 15:04:05 -0700",
		timeFormatAlt: "2006-01-02 15:04:05 MST",
	}
}

// setter methods
// SetUserIndex will set userIndex
func (b *baseParser) SetUserIndex(userIndex int) *baseParser {
	b.userIndex = &userIndex
	return b
}

// SetHostIndex will set hostIndex
func (b *baseParser) SetHostIndex(hostIndex int) *baseParser {
	b.hostIndex = &hostIndex
	return b
}

// SetDatabaseIndex will set databaseIndex
func (b *baseParser) SetDatabaseIndex(databaseIndex int) *baseParser {
	b.databaseIndex = &databaseIndex
	return b
}

// SetTimeIndex will set timeIndex
func (b *baseParser) SetTimeIndex(timeIndex int) *baseParser {
	b.timeIndex = &timeIndex
	return b
}

// SetLogLevelIndex will set logLevelIndex
func (b *baseParser) SetLogLevelIndex(logLevelIndex int) *baseParser {
	b.levelIndex = logLevelIndex
	return b
}

// Parse will parse log line and return error if any
func (b *baseParser) Parse(line string) (ParsedData, error) {
	if !b.regex.MatchString(line) {
		return nil, fmt.Errorf("invalid log format")
	}

	parsedData := NewParsedData(b)
	var data utils.StringSlice = b.regex.FindStringSubmatch(line)
	parsedData.SetParsedData(data)

	if b.timeIndex == nil {
		return parsedData, nil
	}

	// parsing time
	timePart := data.Get(*b.timeIndex)
	if timePart == "" {
		return parsedData, nil
	}

	t, err := time.Parse(b.timeFormat, timePart)
	if err == nil {
		parsedData.SetParsedTime(t)
		return parsedData, nil
	}

	b.timeFormat, b.timeFormatAlt = b.timeFormatAlt, b.timeFormat
	t, err = time.Parse(b.timeFormat, timePart)
	if err != nil {
		return nil, err
	}

	parsedData.SetParsedTime(t)

	return parsedData, nil
}
