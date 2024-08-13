package parselog

import (
	"context"
	"fmt"
	"sync"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/queryparser"
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
	cnf        *config.Config
	baseParser BaseParser

	piiRunner *piiscanner.PiiScanner

	piiResp map[piiscanner.PIILabel][]PIIResp
	mt      sync.Mutex
}

// NewQueryParser is a constructor that creates a new QueryParser object.
func NewQueryParser(cnf *config.Config, baseParser BaseParser) *QueryParser {
	return &QueryParser{
		cnf:        cnf,
		baseParser: baseParser,

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
func (u *QueryParser) Feed(line string) error {
	parsedData, err := u.baseParser.Parse(line)
	if err != nil {
		return err
	}

	// if time is not valid then return
	if !u.cnf.LogParser.IsValidTime(parsedData.GetTime()) {
		return nil
	}

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
