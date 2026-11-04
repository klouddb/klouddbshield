package piiscanner

import (
	"context"
	"fmt"
)

// PiiScanner uses column and value detectors together (query-log PII parsing).
type PiiScanner struct {
	columnDetector []Detector
	valueDetector  []Detector
}

func NewPiiScanner() *PiiScanner {
	return &PiiScanner{}
}

func (p *PiiScanner) AddColumnDetector(d Detector) *PiiScanner {
	p.columnDetector = append(p.columnDetector, d)
	return p
}

func (p *PiiScanner) AddValueDetector(d Detector) *PiiScanner {
	p.valueDetector = append(p.valueDetector, d)
	return p
}

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

func (p *PiiScanner) Detect(ctx context.Context, column, value string) (PIILabel, error) {
	if value == "" || value == "?" {
		return "", nil
	}

	columnLabels := make(map[PIILabel]struct{})
	for _, d := range p.columnDetector {
		labels, err := d.Detect(ctx, column, nil)
		if err != nil {
			return "", err
		}
		for _, label := range labels {
			if label.PIILabel != "" {
				columnLabels[label.PIILabel] = struct{}{}
			}
		}
	}

	columnContext := make(ColumnContext)
	for label := range columnLabels {
		columnContext[label] = true
	}

	valueLabels := make(map[PIILabel]struct{})
	for _, d := range p.valueDetector {
		labels, err := d.Detect(ctx, value, columnContext)
		if err != nil {
			return "", err
		}
		for _, label := range labels {
			if label.PIILabel != "" {
				valueLabels[label.PIILabel] = struct{}{}
			}
		}
	}

	if len(valueLabels) == 0 {
		for label := range columnLabels {
			return label, nil
		}
	}

	for label := range columnLabels {
		if _, ok := valueLabels[label]; ok {
			return label, nil
		}
	}

	return "", nil
}
