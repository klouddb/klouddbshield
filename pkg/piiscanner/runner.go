package piiscanner

import (
	"context"
	"fmt"
)

// PiiScanner is a detector which uses multiple detectors to detect
// PIILabels for columns and values.
//
// This is implmentation for Detector interface in detector.go.
//
//	````````````````````````````
//	type Detector interface {
//		Init() error
//		Detect(ctx context.Context, word string) (PIILabel, error)
//	}
//	````````````````````````````
//
// It supports two types of detectors: column and value detectors.
// Column detectors are used to detect PIILabels for column names.
// Value detectors are used to detect PIILabels for values.
type PiiScanner struct {
	// columnDetector is a list of detectors used to detect PIILabels for column names.
	columnDetector []Detector

	// valueDetector is a list of detectors used to detect PIILabels for values.
	valueDetector []Detector
}

// NewPiiScanner creates a new PiiScanner instance.
func NewPiiScanner() *PiiScanner {
	return &PiiScanner{}
}

// AddColumnDetector adds a new column detector to the list of column detectors.
func (p *PiiScanner) AddColumnDetector(d Detector) *PiiScanner {
	p.columnDetector = append(p.columnDetector, d)
	return p
}

// AddValueDetector adds a new value detector to the list of value detectors.
func (p *PiiScanner) AddValueDetector(d Detector) *PiiScanner {
	p.valueDetector = append(p.valueDetector, d)
	return p
}

// Init initializes all detectors.
// It returns an error if no column or value detector is added.
// It returns an error if any detector fails to initialize.
//
// To run PiiScanner we need at least one column and one value detector.
func (p *PiiScanner) Init() error {
	if len(p.columnDetector) == 0 || len(p.valueDetector) == 0 {
		return fmt.Errorf("At least one column and one value detector must be added")
	}

	for _, d := range p.columnDetector {
		if err := d.Init(); err != nil {
			return err
		}
	}

	for _, d := range p.valueDetector {
		if err := d.Init(); err != nil {
			return err
		}
	}
	return nil
}

// Detect checks the column and value against all detectors and
// returns the first match.
//
// If no value labels are detected then it returns the column label.
// If there is value labels detected then it return a label which is
// common in both column and value labels.
func (p *PiiScanner) Detect(ctx context.Context, column, value string) (PIILabel, error) {
	if value == "" || value == "?" {
		return "", nil
	}

	// get label from all column detectors and store them in a map
	columnLabels := make(map[PIILabel]struct{})
	for _, d := range p.columnDetector {
		labels, err := d.Detect(ctx, column)
		if err != nil {
			return "", err
		}
		for _, label := range labels {
			if label.PIILabel != "" {
				columnLabels[label.PIILabel] = struct{}{}
			}
		}
	}

	// get label from all value detectors and store them in a map
	valueLabels := make(map[PIILabel]struct{})
	for _, d := range p.valueDetector {
		labels, err := d.Detect(ctx, value)
		if err != nil {
			return "", err
		}
		for _, label := range labels {
			if label.PIILabel != "" {
				valueLabels[label.PIILabel] = struct{}{}
			}
		}
	}

	// if there is no value labels then we can assume that the value is not a PII
	if len(valueLabels) == 0 {
		for label := range columnLabels {
			return label, nil
		}
	}

	// if there is a common label in both column and value labels then return that label
	for label := range columnLabels {
		if _, ok := valueLabels[label]; ok {
			return label, nil
		}
	}

	return "", nil
}
