package piiscanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/pkg/utils"
	"golang.org/x/sync/errgroup"
)

type TableScannerOutput struct {
	TableName  string
	PiiDataMap map[string]PiiData
}

type PiiData struct {
	ValueMap  PiiLabelMap
	ColumnMap PiiLabelMap
}

type WeightWithCount struct {
	Weight float64
	Count  int
}

type PiiLabelMap map[string] /* detector name */ map[PIILabel]WeightWithCount

func NewPiiLabelMap() PiiLabelMap {
	return make(map[string]map[PIILabel]WeightWithCount)
}

func NewPiiLabelMapFromPiiLableWithWeight(detector string, l []PiiLabelWithWeight) PiiLabelMap {
	m := make(map[PIILabel]WeightWithCount)
	for _, v := range l {
		piiData := m[v.PIILabel]
		piiData.Weight += v.Weight
		piiData.Count++
		m[v.PIILabel] = piiData
	}
	return map[string]map[PIILabel]WeightWithCount{
		detector: m,
	}
}

func (p PiiLabelMap) Add(detector string, label PIILabel, weight float64) {
	if _, ok := p[detector]; !ok {
		p[detector] = make(map[PIILabel]WeightWithCount)
	}
	w := p[detector][label]
	w.Weight += weight
	w.Count++

	p[detector][label] = w
}

func (p PiiLabelMap) GetMax() PIILabel {
	_, label, _ := p.GetMaxWithWeight()
	return label
}

func (p PiiLabelMap) GetMaxWithWeight() (string, PIILabel, WeightWithCount) {
	var maxLabel PIILabel
	var maxScore WeightWithCount
	var detectorName string

	for name, m := range p {
		// fmt.Println("label", label, "score", score)
		for label, score := range m {
			if score.Weight > maxScore.Weight {
				maxLabel = label
				maxScore = score
				detectorName = name
			}
		}
	}

	return detectorName, maxLabel, maxScore
}

type TableScanManager struct {
	// workers []*TableScanWorker
	output map[string]TableScannerOutput

	detectorFactory func() []Detector

	columnDetector Detector

	inputChan  chan ScanInput
	outputChan chan ScanOutput
	errorChan  chan error

	workerGroup errgroup.Group

	valueCount map[string]map[string]int
}

func NewTableScanManager() *TableScanManager {
	return &TableScanManager{
		valueCount: make(map[string]map[string]int),
	}
}

func (t *TableScanManager) WithDetectorFactory(factory func() []Detector) *TableScanManager {
	t.detectorFactory = factory
	return t
}

func (t *TableScanManager) WithColumnDetector(detector Detector) *TableScanManager {
	t.columnDetector = detector
	return t
}

func (t *TableScanManager) Start(ctx context.Context, n int) error {
	if t.columnDetector == nil {
		return fmt.Errorf("no detector available")
	}

	err := t.columnDetector.Init()
	if err != nil {
		return err
	}

	t.outputChan = make(chan ScanOutput)
	t.output = make(map[string]TableScannerOutput)
	go t.OutputRunner()

	if t.detectorFactory == nil {
		return nil
	}

	// t.workers = make([]*TableScanWorker, 0, n)
	// channel size 100 is required to prevent deadlock
	t.inputChan = make(chan ScanInput, 100)
	t.errorChan = make(chan error, 1)
	fmt.Println("> Initialising table scan manager")

	g := errgroup.Group{}

	for i := 0; i < n; i++ {
		g.Go(func() error {
			detectors := t.detectorFactory()
			for _, detector := range detectors {
				err := detector.Init()
				if err != nil {
					return err
				}
			}

			worker := NewTableScanWorker(t.inputChan, t.outputChan, detectors)
			t.workerGroup.Go(func() error {
				return worker.Start(ctx)
			})
			return nil
			// t.workers = append(t.workers, worker)
		})
	}

	err = g.Wait()
	if err != nil {
		return err
	}

	go func() {
		err := t.workerGroup.Wait()
		t.errorChan <- err
		close(t.errorChan)
	}()

	return nil
}

func (t *TableScanManager) Output() (_ map[string]TableScannerOutput, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	if t.errorChan != nil {
		close(t.inputChan)
		err = <-t.errorChan
		if err != nil {
			return nil, err
		}
	}

	close(t.outputChan)

	return t.output, nil
}

func (t *TableScanManager) PushValue(input ScanInput) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	if input.Value == "" {
		return nil
	}

	v := strings.TrimSpace(input.Value)
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "{", "")
	if v == "" {
		return nil
	}

	tableMap := t.valueCount[input.Tablename]
	if tableMap == nil {
		tableMap = make(map[string]int)
		t.valueCount[input.Tablename] = tableMap
	}

	tableMap[input.ColumnName]++

	newInput := func(s string) ScanInput {
		i := input
		i.Value = s
		return i
	}

	lines := strings.Split(v, "\n")

	for _, line := range lines {

		if len(line) < 512 {
			i := newInput(line)
			err := t.pushDevidedInput(i)
			if err != nil {
				return err
			}
			continue
		}

		chunks := utils.Chunks(line, 512)
		for _, chunk := range chunks {
			i := newInput(chunk)
			err = t.pushDevidedInput(i)
			if err != nil {
				return err
			}
		}
	}
	// fmt.Println("Pushed value", input.Value, "to input channel")

	return nil
}

func (t *TableScanManager) pushDevidedInput(input ScanInput) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	// if t.numbOfWorker.Load() == 0 {
	// 	return fmt.Errorf("no worker available")
	// }

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	select {
	case t.inputChan <- input:
	case <-timeout.C:
		return fmt.Errorf("input value timeout")
	case err = <-t.errorChan:
		return fmt.Errorf("worker error: %v", err)
	}
	return nil
}

func (t *TableScanManager) PushColumn(ctx context.Context, input ScanInput) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	// for push column, we are expecting value as number or rows for that column
	if t.columnDetector == nil {
		return fmt.Errorf("no column detector available")
	}

	labels, err := t.columnDetector.Detect(ctx, input.ColumnName)
	if err != nil {
		return err
	}

	// updated weight based on number of rows
	for i, v := range labels {
		labels[i].Weight = v.Weight
	}

	t.outputChan <- ScanOutput{
		Type:      "column",
		ScanInput: input,
		Detector:  "regex",
		Labels:    labels,
	}

	return nil
}

func (t *TableScanManager) OutputRunner() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered OutputRunner", r)
		}
	}()

	// f, err := os.Create("detailed_output.csv")
	// if err != nil {
	// 	fmt.Println("Error creating file", err)
	// }

	// csvFile := csv.NewWriter(f)
	for output := range t.outputChan {
		if _, ok := t.output[output.Tablename]; !ok {
			t.output[output.Tablename] = TableScannerOutput{
				TableName:  output.Tablename,
				PiiDataMap: make(map[string]PiiData),
			}
		}

		if _, ok := t.output[output.Tablename].PiiDataMap[output.ColumnName]; !ok {
			t.output[output.Tablename].PiiDataMap[output.ColumnName] = PiiData{
				ColumnMap: NewPiiLabelMap(),
				ValueMap:  NewPiiLabelMap(),
			}
		}

		m := t.output[output.Tablename].PiiDataMap[output.ColumnName].ValueMap
		if output.Type == "column" {
			m = t.output[output.Tablename].PiiDataMap[output.ColumnName].ColumnMap
		}

		for _, label := range output.Labels {
			// csvFile.Write([]string{output.Tablename, output.ColumnName, output.Value, // nolint:errcheck
			// 	output.Type, string(label.PIILabel), fmt.Sprintf("%f", label.Weight)})
			m.Add(output.Detector, label.PIILabel, label.Weight)
		}
	}
	// csvFile.Flush()
}
