package piiscanner

import (
	"context"
	"embed"
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"testing"
)

// Embed pii test data file
//
//go:embed pii_test_data/*.csv
var testdata embed.FS

func Test_CsvTesting_RegexpDetector(t *testing.T) {

	files, err := testdata.ReadDir("pii_test_data")
	if err != nil {
		t.Fatalf("failed to open test data file: %v", err)
		return
	}

	detectors := map[string]Detector{}

	detectors["value"] = NewRegexValueDetector()
	detectors["column"] = NewRegexColumnDetector()

	for _, d := range detectors {
		err = d.Init()
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
			return
		}
	}

	totalCountMap := map[string]int{}
	successCountMap := map[string]int{}
	falsePositiveCountMap := map[string]int{}

	for _, file := range files {
		fmt.Println(file.Name())
		f, err := testdata.Open("pii_test_data/" + file.Name())
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
			return
		}

		csvReader := csv.NewReader(f)

		line := 0
		for {
			line++
			data, err := csvReader.Read()
			if err != nil {
				if err == io.EOF {
					break
				}
				t.Errorf("Expected no error, got %v, file %s:%d", err, file.Name(), line)
				return
			}

			if len(data) < 3 {
				continue
			}

			totalCountMap[data[0]+" - "+data[2]]++
			d := detectors[data[0]]
			if d == nil {
				t.Errorf("Expected detector, got nil, file %s:%d", file.Name(), line)
				continue
			}

			labels, err := d.Detect(context.Background(), data[1])
			if err != nil {
				t.Errorf("Expected no error, got %v, file %s:%d", err, file.Name(), line)
				continue
			}
			outputLabel := NewPiiLabelMapFromPiiLableWithWeight("regex", labels).GetMax()
			if outputLabel != PIILabel(data[2]) {
				falsePositiveCountMap[data[0]+" - "+string(outputLabel)]++
				t.Errorf("Expected label %v, got %v (%v), file %s:%d data %s", data[2], outputLabel, labels, file.Name(), line, data[1])
			} else {
				successCountMap[data[0]+" - "+data[2]]++
			}
		}

		fmt.Println("Test passed", file.Name())

	}

	// count table for all labels
	for k, v := range totalCountMap {
		fmt.Println(k, v, successCountMap[k], float64(successCountMap[k])/float64(v), falsePositiveCountMap[k])
	}

}
