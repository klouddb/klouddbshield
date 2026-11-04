package piiscanner

import (
	"regexp"
	"unicode/utf8"

	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// Legacy ignore rules. DPDPA's IgnoreColumn is stricter (ToLower + narrower _date
// patterns) and would change empty-region Postgres scans.
var (
	ignoreRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(created|updated|deleted|committed)_(at|by|on)$`),
		// regexp.MustCompile(`(?i)_id$`), // this is failing. here we need to all _id accept email_id
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

// PiiEntitiesForWeightMergeLogic is used for the legacy (non-India) weight-merge path.
var PiiEntitiesForWeightMergeLogic = utils.NewSetFromSlice([]PIILabel{
	PIILabel_DrivingLicenceNumber,
	PIILabel_CreditCard,
	PIILabel_Phone,
	PIILabel_ZipCode,
	PIILabel_NHSNumber,
})

// WeightMergeEntities returns the weight-merge entity set for the given region.
// India uses DPDPA's exported set so new entities appear after a module bump.
func WeightMergeEntities(region string) utils.Set[PIILabel] {
	if IsIndiaRegion(region) {
		return utils.NewSetFromSlice(dpdpa.WeightMergeLabels())
	}
	return PiiEntitiesForWeightMergeLogic
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
