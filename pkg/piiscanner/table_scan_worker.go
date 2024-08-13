package piiscanner

import (
	"context"
	"fmt"
)

type ScanInput struct {
	Tablename  string
	ColumnName string
	Value      string
}

type ScanOutput struct {
	Type string
	ScanInput
	Detector string
	Labels   []PiiLabelWithWeight
}

type TableScanWorker struct {
	inputChan  chan ScanInput
	outputChan chan ScanOutput

	detectors []Detector
}

func NewTableScanWorker(inputChan chan ScanInput, outputChan chan ScanOutput, detectors []Detector) *TableScanWorker {
	return &TableScanWorker{
		inputChan:  inputChan,
		outputChan: outputChan,
		detectors:  detectors,
	}
}

func (t *TableScanWorker) Start(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	for data := range t.inputChan {
		if data.Value == "" || data.Value == "<nil>" {
			continue
		}

		// detectorLoop:
		for _, detector := range t.detectors {
			labels, err := detector.Detect(ctx, data.Value)
			if err != nil {
				return fmt.Errorf("error detecting pii data: from %s (%v)", detector.Name(), err)
			}

			// for _, v := range labels {
			// 	if v.Weight == 1.0 {
			// 		t.outputChan <- ScanOutput{
			// 			Type:      "value",
			// 			ScanInput: data,
			// 			Labels:    labels,
			// 		}
			// 		break detectorLoop
			// 	}

			t.outputChan <- ScanOutput{
				Type:      "value",
				ScanInput: data,
				Detector:  detector.Name(),
				Labels:    labels,
			}
		}
	}

	return nil
}
