package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
)

func TestFastRunner(t *testing.T) {
	testRunParser(t, RunFastParser)
}

// func TestRunnerFunc(t *testing.T) {
// 	testRunParser(t, RunParser)
// }

func testRunParser(t *testing.T, runner func(ctx context.Context, cnf *config.Config, fn, validator ParserFunc)) {
	// Define the test cases as a table
	testCases := []struct {
		name         string
		logFile      io.Reader
		expectedLogs []string
	}{
		{
			name: "Successful parsing",
			logFile: strings.NewReader(`Line 1
Line 2
Line 4
Line 5
`),
			expectedLogs: []string{
				"Line 1",
				"Line 2",
				"Line 4",
				"Line 5",
			},
		},
		{
			name: "Parsing error",
			logFile: strings.NewReader(`Line 1
Line 2
Line 3
Line 4
Line 5
`),
			expectedLogs: []string{
				"Line 1",
				"Line 2",
				"Line 4",
				"Line 5",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary file to simulate log file
			tempFile, err := os.CreateTemp("", "test.log")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tempFile.Name())

			// Copy the content of the test log file to the temporary file
			_, err = io.Copy(tempFile, tc.logFile)
			if err != nil {
				t.Fatal(err)
			}
			tempFile.Close()

			// Set up the test configuration
			cnf := &config.Config{
				LogParser: &config.LogParser{
					LogFiles: []string{tempFile.Name()},
				},
			}

			// Define a mock parser function for testing
			var receivedLogs []string
			mockParserFunc := func(line string) error {
				if line == "Line 3" {
					return errors.New("error parsing line")
				}
				receivedLogs = append(receivedLogs, line)
				// Simulate some processing
				time.Sleep(100 * time.Millisecond)
				return nil
			}

			// Run the parser
			runner(context.TODO(), cnf, mockParserFunc, mockParserFunc)

			// Verify that all lines from the file are received in the mock function
			if !stringSlicesEqual(receivedLogs, tc.expectedLogs) {
				t.Errorf("Received logs mismatch.\nExpected: %v\nGot: %v", tc.expectedLogs, receivedLogs)
			}
		})
	}
}

// Helper function to compare two string slices
func stringSlicesEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}
