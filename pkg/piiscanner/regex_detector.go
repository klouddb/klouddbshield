package piiscanner

import (
	"context"
	"fmt"
	"strings"

	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

// baseRegexDetector is a base helper for regex detectors.
// It contains a map of PIILabel for list of regexes. And also check
// all regexes for each PIILabel and return the first match.
//
// To Create Any new regex detector, you can embed this struct and
// implement Init() method which populate the map with PIILabel and
// list of regexes.
type baseRegexDetector struct {
	m                map[PIILabel][]RegexWithWeight
	isColumnDetector bool
}

func (r *baseRegexDetector) Name() string {
	return "regex"
}

// Detect checks the word against all regexes for each PIILabel and
// returns the first match.
func (r *baseRegexDetector) Detect(ctx context.Context, word string, columnContext ColumnContext) ([]PiiLabelWithWeight, error) {
	if r.m == nil {
		return nil, fmt.Errorf("regex detector not initialized")
	}

	word = strings.ToLower(word)

	var out []PiiLabelWithWeight
	for label, regexes := range r.m {
		for _, v := range regexes {
			if v.RequiresColumnContext {
				if columnContext == nil || !columnContext[label] {
					continue
				}
			}
			if v.Regexp.MatchString(word) {
				matched := v.Regexp.FindString(word)
				if !r.isColumnDetector && label == PIILabel_CreditCard {
					cleaned := strings.NewReplacer(
						" ", "",
						"-", "",
						"+", "",
					).Replace(matched)

					if !LuhnValid(cleaned) {
						continue
					}
				}
				out = append(out, PiiLabelWithWeight{
					PIILabel: label,
					Weight:   v.Weight,
				})
				break
			}
		}
	}

	return out, nil
}

// regexColumnDetector is a detector which uses regexes to detect
// PIILabels for columns.
//
// It uses some common regexes for some known column name patterns.
type regexColumnDetector struct {
	*baseRegexDetector
	region string
}

// NewRegexColumnDetector returns a new regex column detector
func NewRegexColumnDetector() Detector {
	return NewRegexColumnDetectorForRegion("")
}

// NewRegexColumnDetectorForRegion returns a new regex column detector for the
// given region. Use RegionIndia for DPDPA package detectors, or empty for the
// legacy entity set (updated credit-card handling only).
func NewRegexColumnDetectorForRegion(region string) Detector {
	if IsIndiaRegion(region) {
		return dpdpa.NewIndiaColumnDetector()
	}
	return &regexColumnDetector{
		baseRegexDetector: &baseRegexDetector{
			isColumnDetector: true,
		},
		region: region,
	}
}

// Init populates column regexes for the legacy (non-India) entity set.
func (r *regexColumnDetector) Init() error {
	return r.initDefault()
}

// regexValueDetector is a detector which uses regexes to detect
// PIILabels for values.
//
// It uses some common regexes for some known value patterns.
type regexValueDetector struct {
	*baseRegexDetector
	region string
}

// NewRegexValueDetector returns a new regex value detector
func NewRegexValueDetector() Detector {
	return NewRegexValueDetectorForRegion("")
}

// NewRegexValueDetectorForRegion returns a new regex value detector for the
// given region. Use RegionIndia for DPDPA package detectors, or empty for the
// legacy entity set (updated credit-card handling only).
func NewRegexValueDetectorForRegion(region string) Detector {
	if IsIndiaRegion(region) {
		return dpdpa.NewIndiaValueDetector()
	}
	return &regexValueDetector{
		baseRegexDetector: &baseRegexDetector{},
		region:            region,
	}
}

// Init populates value regexes for the legacy (non-India) entity set.
func (r *regexValueDetector) Init() error {
	return r.initDefault()
}
