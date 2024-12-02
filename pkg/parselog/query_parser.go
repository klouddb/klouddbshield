package parselog

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/queryparser"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// PIIResp is a struct that holds the column and value of the PII data.
// This struct is used to store the PII data that is detected in the query.
type PIIResp struct {
	Col string
	Val string
}

// QueryParser is helper struct that is used to parse the query from the log
// and detect the PII data in the query.
//
// It uses the BaseParser to parse the log and the PiiScanner to detect the PII data.
// The PII data is stored in the map with the PIILabel as the key and the PIIResp as the value.
type QueryParser struct {
	cnf *config.Config

	piiRunner *piiscanner.PiiScanner

	piiResp map[piiscanner.PIILabel][]PIIResp
	mt      sync.Mutex
}

// NewQueryParser is a constructor that creates a new QueryParser object.
func NewQueryParser(cnf *config.Config) *QueryParser {
	return &QueryParser{
		cnf: cnf,

		piiRunner: piiscanner.NewPiiScanner().
			AddValueDetector(piiscanner.NewRegexValueDetector()).
			AddValueDetector(piiscanner.NewSpacyDetector().WithWorkDirs([]string{"python", "/etc/klouddbshield/python", "../../python"})).
			AddColumnDetector(piiscanner.NewRegexColumnDetector()),

		piiResp: make(map[piiscanner.PIILabel][]PIIResp),
	}
}

// Init is a function that triggers initialization of the pii runner.
func (u *QueryParser) Init() error {
	return u.piiRunner.Init()
}

// Feed is a function that takes a line of log as input and parses the query
// from the log and detects the PII data in the query.
func (u *QueryParser) Feed(parsedData ParsedData) error {

	msg := parsedData.GetDescription()
	query, ok := queryparser.GetQueryFromMessage(msg)
	if !ok {
		return nil
	}

	return u.processQuery(query)
}

func (u *QueryParser) processQuery(query string) error {
	if query == "" {
		return nil
	}

	kvs, err := queryparser.ParseSqlQuery(query)
	if kvs == nil {
		return err
	}

	for _, kv := range kvs.GetAll() {
		label, err := u.piiRunner.Detect(context.Background(), kv.Column, string(kv.Value))
		if err != nil {
			fmt.Println("got error", err)
			return err
		}

		if label != "" {
			u.AddKV(label, &kv)
		}

	}

	return err
}

func (u *QueryParser) AddKV(label piiscanner.PIILabel, kv *queryparser.KVPair) {
	u.mt.Lock()
	defer u.mt.Unlock()

	u.piiResp[label] = append(u.piiResp[label], PIIResp{
		Col: kv.Column,
		Val: string(kv.Value),
	})
}

func (u *QueryParser) GetPII() map[piiscanner.PIILabel][]PIIResp {
	u.mt.Lock()
	defer u.mt.Unlock()

	return u.piiResp
}

type SqlInjectionScanner struct {
	cnf *config.LogParser

	queryRegex []*regexp.Regexp

	errorRegex []*regexp.Regexp

	errorCodes utils.Set[string]

	result *utils.LockSet
}

func NewSqlInjectionScanner(cnf *config.LogParser) *SqlInjectionScanner {
	return &SqlInjectionScanner{
		cnf: cnf,

		queryRegex: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SELECT\s+usename[\s\n]+FROM\s+pg_user`),
			regexp.MustCompile(`(?i)SELECT\s+DISTINCT\s*\(\s*usename\s*\)[\s\n]+FROM\s+pg_user[\s\n]+ORDER\s+BY\s+usename\s+OFFSET\s+\d+\s+LIMIT\s+1`),
			regexp.MustCompile(`(?i)SELECT\s+COUNT\s*\(\s*DISTINCT\s*\(\s*usename\s*\)\s*\)[\s\n]+FROM\s+pg_user`),
			regexp.MustCompile(`(?i)SELECT\s+usename\s*,\s*passwd[\s\n]+FROM\s+pg_shadow`),
			regexp.MustCompile(`(?i)SELECT\s+DISTINCT\s*\(\s*passwd\s*\)[\s\n]+FROM\s+pg_shadow[\s\n]+WHERE\s+usename\s*=\s*'\w+'[\s\n]+OFFSET\s+\d+[\s\n]+LIMIT\s+1`),
			regexp.MustCompile(`(?i)SELECT\s+COUNT\s*\(\s*DISTINCT\s*\(\s*passwd\s*\)\s*\)[\s\n]+FROM\s+(?:pg_shadow)[\s\n]+WHERE\s+usename\s*=\s*'\w+'`),
		},

		/*
			no pg_hba.conf entry for host "123.123.123.123", user "andym", database "testdb"
			password authentication failed for user "andym"
			user "andym" does not exist
			role "root" does not exist
			database "testdb" does not exist
			Connection to Server Failed: Connection Refused
		*/

		errorRegex: []*regexp.Regexp{
			regexp.MustCompile(`(?i)no\s+pg_hba\.conf\s+entry\s+for\s+host\s+"[^"]+",\s+user\s+"[^"]+",\s+database\s+"[^"]+"`),
			regexp.MustCompile(`(?i)password\s+authentication\s+failed\s+for\s+user\s+"[^"]+"`),
			regexp.MustCompile(`(?i)user\s+"[^"]+"\s+does\s+not\s+exist`),
			regexp.MustCompile(`(?i)role\s+"[^"]+"\s+does\s+not\s+exist`),
			regexp.MustCompile(`(?i)database\s+"[^"]+"\s+does\s+not\s+exist`),
			regexp.MustCompile(`(?i)Connection\s+to\s+Server\s+Failed:\s+Connection\s+Refused`),
		},

		errorCodes: utils.NewSetFromSlice([]string{
			"42000",
			"42601",
			"42501",
			"3F000",
			"28000",
			"28P01",
			"42809",
			"42703",
			"42883",
			"42P01",
			"42P02",
			"42704",
			"42501",
		}),

		result: utils.NewLockSet(),
	}
}

func (u *SqlInjectionScanner) Feed(parsedData ParsedData) error {

	msg := parsedData.GetDescription()
	if query, ok := queryparser.GetQueryFromMessage(msg); ok {
		for _, r := range u.queryRegex {
			if r.MatchString(query) {
				u.result.Add(query)
				break
			}
		}
	}

	// TODO add falat check
	for _, r := range u.errorRegex {
		if r.MatchString(msg) {
			u.result.Add(msg)
			break
		}
	}

	if errorCode, err := parsedData.GetErrorCode(); err == nil {
		if u.errorCodes.Contains(errorCode) {
			u.result.Add("Error code found from logfile " + errorCode)
		}
	}

	return nil
}

func (u *SqlInjectionScanner) GetQueries() []string {
	out := make([]string, 0)
	u.result.ForEach(
		func(k string, _ bool) {
			out = append(out, k)
		},
	)

	return out
}
