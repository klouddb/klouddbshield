package parselog

import (
	"regexp"
	"strings"
	"sync"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/hbarules"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

var LogPrefixPostgresIpsRegexp = regexp.MustCompile(`(\s*)connection received:(\s+)host=(\S+)?(\s+)port=(\d+)?`)
var UserConnAuthRegexp = regexp.MustCompile(`(\s*)connection authorized:(\s+)user=(\S*)(\s+)database=(\S*)(\s+)application_name=(\S*)`)

type UniqueIPParser struct {
	uniqueIPs    *utils.LockSet
	logParserCnf *config.LogParser
}

func NewUniqueIPParser(logParserCnf *config.LogParser) *UniqueIPParser {
	return &UniqueIPParser{
		uniqueIPs:    utils.NewLockSet(),
		logParserCnf: logParserCnf,
	}
}

func (u *UniqueIPParser) Feed(parsedData ParsedData) error {

	// if logline prefix contains %h then use base parser then try parsing loglineprefix
	if strings.Contains(u.logParserCnf.PgSettings.LogLinePrefix, "%h") || strings.Contains(u.logParserCnf.PgSettings.LogLinePrefix, "%r") {
		if host, err := parsedData.GetHost(); err == nil {
			u.uniqueIPs.Add(host)
			return nil
		}
	}

	// if logConnection is not enabled then return as below logic
	// is dependent on logConnection
	if !u.logParserCnf.PgSettings.LogConnections {
		return nil
	}

	desc := parsedData.GetDescription()
	if !LogPrefixPostgresIpsRegexp.MatchString(desc) {
		return nil
	}

	var parts utils.StringSlice = LogPrefixPostgresIpsRegexp.FindStringSubmatch(desc)

	u.uniqueIPs.Add(parts.Get(3))
	return nil
}

func (u *UniqueIPParser) GetUniqueIPs() map[string]bool {
	return u.uniqueIPs.GetAll()
}

type UniqueUserParser struct {
	uniqueUsers  *utils.LockSet
	logParserCnf *config.LogParser
}

func NewUserParser(logParserCnf *config.LogParser) *UniqueUserParser {
	return &UniqueUserParser{
		uniqueUsers:  utils.NewLockSet(),
		logParserCnf: logParserCnf,
	}
}

func (u *UniqueUserParser) Feed(parsedData ParsedData) error {

	if strings.Contains(u.logParserCnf.PgSettings.LogLinePrefix, "%u") {
		if user, err := parsedData.GetUser(); err == nil {
			u.uniqueUsers.Add(user)
			return nil
		}
	}

	if !u.logParserCnf.PgSettings.LogConnections {
		return nil
	}

	desc := parsedData.GetDescription()
	if !UserConnAuthRegexp.MatchString(desc) {
		return nil
	}

	var parts utils.StringSlice = UserConnAuthRegexp.FindStringSubmatch(desc)

	u.uniqueUsers.Add(parts.Get(3))

	return nil
}

func (u *UniqueUserParser) GetUniqueUser() map[string]bool {
	return u.uniqueUsers.GetAll()
}

type HbaUnusedLineParser struct {
	logParserCnf *config.LogParser

	hbafileRulesValidator hbarules.HbaRuleValidator
	mt                    sync.Mutex
}

func NewHbaUnusedLines(logParserCnf *config.LogParser, hbafileRulesValidator hbarules.HbaRuleValidator) *HbaUnusedLineParser {
	return &HbaUnusedLineParser{
		logParserCnf: logParserCnf,

		hbafileRulesValidator: hbafileRulesValidator,
	}
}

func (u *HbaUnusedLineParser) Feed(parsedData ParsedData) error {

	user, err := parsedData.GetUser()
	if err != nil {
		if !u.logParserCnf.PgSettings.LogConnections {
			return nil
		}

		desc := parsedData.GetDescription()
		if !UserConnAuthRegexp.MatchString(desc) {
			return nil
		}

		var parts utils.StringSlice = UserConnAuthRegexp.FindStringSubmatch(desc)

		user = parts.Get(3)
		if user == "" {
			return nil
		}
	}

	host, err := parsedData.GetHost()
	if err != nil {
		if !u.logParserCnf.PgSettings.LogConnections {
			return nil
		}

		desc := parsedData.GetDescription()
		if !LogPrefixPostgresIpsRegexp.MatchString(desc) {
			return nil
		}

		var parts utils.StringSlice = LogPrefixPostgresIpsRegexp.FindStringSubmatch(desc)

		host = parts.Get(3)
		if host == "" {
			return nil
		}
	}

	database, err := parsedData.GetDatabase()
	if err != nil {
		if !u.logParserCnf.PgSettings.LogConnections {
			return nil
		}

		desc := parsedData.GetDescription()
		if !UserConnAuthRegexp.MatchString(desc) {
			return nil
		}

		var parts utils.StringSlice = UserConnAuthRegexp.FindStringSubmatch(desc)

		database = parts.Get(5)
		if database == "" {
			return nil
		}
	}

	u.mt.Lock()
	u.hbafileRulesValidator.ValidateEntry(database, user, host)
	u.mt.Unlock()

	return nil
}

func (u *HbaUnusedLineParser) GetUnusedLines() []hbarules.HBARawLine {
	return u.hbafileRulesValidator.GetUnusedLines()
}

type LeakedPasswordResponse struct {
	Query    string
	Password string
}

type PasswordLeakParser struct {
	logParserCnf *config.LogParser

	passwordRegex *regexp.Regexp

	leakPasswordResp []LeakedPasswordResponse
	mt               sync.Mutex

	supportedEncryptionAlgorithms []string
}

func NewPasswordLeakParser(logParserCnf *config.LogParser) *PasswordLeakParser {
	return &PasswordLeakParser{
		logParserCnf:  logParserCnf,
		passwordRegex: regexp.MustCompile(`(?i)PASSWORD\s+'([^']+)'`),

		supportedEncryptionAlgorithms: []string{"md5", "scram-sha-256", "plain", "crypt", "password"},
	}
}

func (u *PasswordLeakParser) Feed(parsedData ParsedData) error {

	msg := parsedData.GetDescription()

	resp := u.passwordRegex.FindStringSubmatch(msg)
	if len(resp) == 0 {
		return nil
	}

	passwordLower := strings.ToLower(resp[1])
	// if it is encrypted password then we can consider it as safe
	for _, alg := range u.supportedEncryptionAlgorithms {
		if strings.HasPrefix(passwordLower, alg) && len(passwordLower) > len(alg) {
			return nil
		}
	}

	u.mt.Lock()
	defer u.mt.Unlock()

	u.leakPasswordResp = append(u.leakPasswordResp, LeakedPasswordResponse{
		Query:    msg,
		Password: resp[1],
	})

	return nil
}

func (u *PasswordLeakParser) GetLeakedPasswords() []LeakedPasswordResponse {
	u.mt.Lock()
	defer u.mt.Unlock()

	return u.leakPasswordResp
}
