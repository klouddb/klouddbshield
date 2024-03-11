package parselog

import (
	"regexp"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

var LogPrefixPostgresIpsRegexp = regexp.MustCompile(`(\s*)connection received:(\s+)host=(\S+)?(\s+)port=(\d+)?`)
var UserConnAuthRegexp = regexp.MustCompile(`(\s*)connection authorized:(\s+)user=(\S*)(\s+)database=(\S*)(\s+)application_name=(\S*)`)

type UniqueIPParser struct {
	uniqueIPs  *utils.LockSet
	cnf        *config.Config
	baseParser BaseParser
}

func NewUniqueIPParser(cnf *config.Config, baseParser BaseParser) *UniqueIPParser {
	return &UniqueIPParser{
		uniqueIPs:  utils.NewLockSet(),
		cnf:        cnf,
		baseParser: baseParser,
	}
}

func (u *UniqueIPParser) Feed(line string) error {

	parsedData, err := u.baseParser.Parse(line)
	if err != nil {
		return err
	}

	// if time is not valid then return
	if !u.cnf.LogParser.IsValidTime(parsedData.GetTime()) {
		return nil
	}

	// if logline prefix contains %h then use base parser then try parsing loglineprefix
	if strings.Contains(u.cnf.LogParser.PgSettings.LogLinePrefix, "%h") || strings.Contains(u.cnf.LogParser.PgSettings.LogLinePrefix, "%r") {
		if host, err := parsedData.GetHost(); err == nil {
			u.uniqueIPs.Add(host)
			return nil
		}
	}

	// if logConnection is not enabled then return as below logic
	// is dependent on logConnection
	if !u.cnf.LogParser.PgSettings.LogConnections {
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

type userParser struct {
	uniqueUsers *utils.LockSet
	cnf         *config.Config

	baseParser BaseParser
}

func NewUserParser(cnf *config.Config, baseParser BaseParser) *userParser {
	return &userParser{
		uniqueUsers: utils.NewLockSet(),
		cnf:         cnf,
		baseParser:  baseParser,
	}
}

func (u *userParser) Feed(line string) error {

	parsedData, err := u.baseParser.Parse(line)
	if err != nil {
		return err
	}

	if !u.cnf.LogParser.IsValidTime(parsedData.GetTime()) {
		return nil
	}

	if strings.Contains(u.cnf.LogParser.PgSettings.LogLinePrefix, "%u") {
		if user, err := parsedData.GetUser(); err == nil {
			u.uniqueUsers.Add(user)
			return nil
		}
	}

	if !u.cnf.LogParser.PgSettings.LogConnections {
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

func (u *userParser) GetUniqueUser() map[string]bool {
	return u.uniqueUsers.GetAll()
}
