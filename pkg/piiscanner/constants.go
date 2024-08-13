package piiscanner

import (
	"regexp"
	"unicode/utf8"

	"github.com/klouddb/klouddbshield/pkg/utils"
)

var (
	ignoreRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(created|updated|deleted|committed)_(at|by|on)$`),
		regexp.MustCompile(`(?i)_id$`), // this is failing. here we need to all _id accept email_id
		regexp.MustCompile(`(?i)^.*timestamp.*$`),
		regexp.MustCompile(`(?i)_date$`),
		regexp.MustCompile(`(?i)_time$`),
	}
	ignoreSet = utils.NewSetFromSlice([]string{
		"user_agent",
		"id",
	})
	dateStringRegex = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^\d{4}[-/]\d{2}[-/]\d{2}`),
		regexp.MustCompile(`(?i)^\d{2}-\d{2}-\d{4}`),
	}
)

type RunOption int

func (r RunOption) String() string {
	for k, v := range RunOptionMap {
		if v == r {
			return k
		}
	}
	return ""
}

type DetectorType string

const (
	RunOption_MetaScan RunOption = iota
	RunOption_DataScan
	RunOption_DeepScan
	RunOption_SpacyScan

	RunOption_MetaScan_String  = "metascan"
	RunOption_DataScan_String  = "datascan"
	RunOption_DeepScan_String  = "deepscan"
	RunOption_SpacyScan_String = "spacyscan"

	RunOption_MetaScan_Title  = "Meta Scan"
	RunOption_DataScan_Title  = "Data Scan"
	RunOption_DeepScan_Title  = "Deep Scan"
	RunOption_SpacyScan_Title = "Spacy Scan"

	DEEPSCAN_WARNINING_LIMIT     = 100000
	DEEPSCAN_SPACY_WARNING_LIMIT = 10000

	DetectorType_ColumnDetector DetectorType = "column detector"
	DetectorType_ValueDetector  DetectorType = "value detector"
)

var OrderMap = map[string]int{
	// for detector type
	string(DetectorType_ValueDetector):  2,
	string(DetectorType_ColumnDetector): 1,

	"regex": 2,
	"spacy": 1,
}

var RunOptionTitleMap = map[RunOption]string{
	RunOption_MetaScan:  RunOption_MetaScan_Title,
	RunOption_DataScan:  RunOption_DataScan_Title,
	RunOption_DeepScan:  RunOption_DeepScan_Title,
	RunOption_SpacyScan: RunOption_SpacyScan_Title,
}

var PiiEntitiesForWeightMergeLogic = utils.NewSetFromSlice([]PIILabel{
	PIILabel_DrivingLicenceNumber,
	PIILabel_CreditCard,
	PIILabel_Phone,
	PIILabel_ZipCode,
	PIILabel_NHSNumber,
})

var RunOptionMap = map[string]RunOption{
	RunOption_MetaScan_String:  RunOption_MetaScan,
	RunOption_DataScan_String:  RunOption_DataScan,
	RunOption_DeepScan_String:  RunOption_DeepScan,
	RunOption_SpacyScan_String: RunOption_SpacyScan,
}

func RunOptionSlice() []string {
	out := make([]string, 0, len(RunOptionMap))
	for k := range RunOptionMap {
		out = append(out, k)
	}
	return out
}

func FilterColumns(columns []string) []string {
	var out []string
	for _, column := range columns {
		if !IgnoreColumn(column) {
			out = append(out, column)
		}
	}
	return out
}

func IgnoreColumn(column string) bool {
	if column == "email_id" {
		return false
	}
	for _, regex := range ignoreRegexes {
		if regex.MatchString(column) {
			return true
		}
	}

	return ignoreSet.Contains(column)
}

func GetValuesString(i interface{}) string {
	switch i := i.(type) {
	case []byte:
		if !utf8.Valid(i) {
			return ""
		}
		if !IsDateString(string(i)) {
			return string(i)
		}
	case string:
		if !IsDateString(i) {
			return i
		}
	default:
		return ""
	}
	return ""
}

func IsDateString(s string) bool {
	for _, regex := range dateStringRegex {
		if regex.MatchString(s) {
			return true
		}
	}
	return false
}
