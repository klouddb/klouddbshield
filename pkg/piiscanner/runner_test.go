package piiscanner

import (
	"context"
	"fmt"
	"testing"
)

func TestRunner(t *testing.T) {
	runner := NewPiiScanner().
		AddValueDetector(NewRegexValueDetector()).
		AddValueDetector(NewSpacyDetector().WithWorkDirs([]string{"../../python"})).
		AddColumnDetector(NewRegexColumnDetector())

	if err := runner.Init(); err != nil {
		t.Errorf("error from init %v", err)
		return
	}

	fmt.Println("Runner initialized successfully")

	inputs := []string{"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536",
		"test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "test", "123", "tera", "tew", "1234", "563445", "3652", "2563", "6536"}
	for _, input := range inputs {
		piiLabel, err := runner.Detect(context.TODO(), input, input)
		if err != nil {
			t.Errorf("Error while processing input %v", err)
			return
		}

		fmt.Println("pii label", piiLabel)
	}

}