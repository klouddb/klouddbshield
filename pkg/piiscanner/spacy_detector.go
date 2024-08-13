package piiscanner

// HOW SPACY DETECTOR WORKS
// SpacyDetector is a detector which uses spacy to detect PIILabels
// for columns and values.
//
// Spacy detector executes a python script which uses spacy to detect
// PIILabels for columns and values.
// Python is located in python/spacy_runner.py
//
// Init function start the python3 python/spacy_runner.py command and
// waits for the message "Successfully loaded model".
// Once that is done we can pass continue input to python script and
// get the PII labels related to the input.
//
// Python script works on continuous input and output. It will keep
// sending the output to the go code and go code will keep sending
// the input to the python script.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	cmdprocessor "github.com/klouddb/klouddbshield/pkg/cmd_processor"
)

// pythonResponse is the response from the python script.
type pythonResponse struct {
	// Type is the type of the response from the python script.
	// Expected values are
	// 	- log:
	// 		if type is log then we can read log from message field
	// 		When processing is started then we will get log
	// 			"Importing required libraries"
	// 		When library is loaded then we will get log
	// 			"Successfully imported required libraries"
	// 		When models are loaded then we will get log
	// 			"Successfully loaded model"
	// 		When python script received any input then we will get log
	// 			"Processing text"
	// 			And text will in data field
	// 	- error:
	// 		if type is error then we can read error message from message field
	// 		and we can ignore the data field
	// 		If there is import error in python script then we will get error
	// 			"Failed to import required libraries"
	// 	 	If there is any other exception in python script then we will get
	//      exception string in message field
	//
	// 	- output: if type is output then we can read the data from data field
	//  - exit: type exit is used to signal go code that python script is done
	Type string `json:"type"`

	// Message is the message from the python script.
	// If type is log or error then we can read the message from this field.
	// If type is output then this field we can ignore.
	Message string `json:"message"`

	// Data is the data from the python script.
	// If type is output then we can read the data from this field.
	// If type is log or error then this field we can ignore.
	Data *Data `json:"data"`
}

// Data is the data structure for the response from the
// python script when pii labels are detected.
type Data struct {
	// Text will be used when we get log "Processing text"
	// This will show what input is received by the python script
	// for processing.
	Text string `json:"text"`

	// Entities is the list of entities detected by the python script.
	// When type is output then we can read the entities from this field.
	// Entities will have the text and label of the detected entities.
	Entities []Entity `json:"entities"`
}

// Entity is the entity detected by the python script.
// Text is the text detected by the python script.
type Entity struct {

	// Text is the text detected by the python script.
	// This is the text for which the label is detected.
	Text string `json:"text"`

	// Label is the label detected by the python script.
	Label string `json:"label"`
}

// spacyFileName is the name of the python script which is used to
// detect the PIILabels using spacy.
const spacyFileName = "spacy_runner.py"

// spacyDetector is the detector which uses spacy to detect PIILabels
// for values.
//
// this detector will load python script from specified workDirs and
// execute the python script to detect PIILabels for values.
type spacyDetector struct {
	// workDirs is the list of directories where the python script
	// can be found.
	workDirs []string

	// cmdProcessor is the command processor which is used to execute
	// the python script and manages the input and output flow between
	// go code and python script.
	cmdProcessor *cmdprocessor.CmdProcessor
}

// NewSpacyDetector returns a new instance of spacyDetector.
func NewSpacyDetector() *spacyDetector {
	return &spacyDetector{}
}

func (u *spacyDetector) Name() string {
	return "spacy"
}

// WithWorkDirs sets the workDirs for the spacyDetector.
func (u *spacyDetector) WithWorkDirs(workDirs []string) *spacyDetector {
	u.workDirs = workDirs
	return u
}

// Init initializes the spacyDetector.
//
// This will valid if python3 is installed or not and then try
// to findout python script from list of work directorues. Then
// will start the python3 python/spacy_runner.py command and
// waits for the message "Successfully loaded model". Once that
// is done we can pass continue input to python script and get
// the PII labels related to the input.
func (u *spacyDetector) Init() error {

	// Check if python3 is installed or not.
	// If python3 is not installed then return error.
	python3, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("Python 3 not found")
	}

	// Detect the working directory where the python script is located.
	// If python script is not found in any of the workDirs then return error.
	fileLocation, err := u.detectWorkingDir()
	if err != nil {
		return err
	}

	// Create the command processor to execute the python script. This will
	// start the python3 python/spacy_runner.py command and waits for the
	// message "Successfully loaded model". Once that is done we can pass
	// continue input to python script and get the PII labels related to the
	// input.
	u.cmdProcessor = cmdprocessor.NewCmdProcessor(python3, path.Join(fileLocation, spacyFileName))

	// Set the skipMethod to skip the log messages and error messages
	// from the python script so that we can only read the output from
	// the python script.
	//
	// skipMethod will return true if we need to skip the message and
	// return false if we need to read the message.
	u.cmdProcessor.SetSkipMethod(func(s string) (bool, error) {

		var out pythonResponse
		err := json.Unmarshal([]byte(s), &out)
		if err != nil {
			return false, fmt.Errorf("Failed to unmarshal the output (%s) in skip method from python script: %v", s, err)
		}

		switch out.Type {
		case "log":
			// we will skip all the log messages from the python script
			// while processing the inputs as we are only interested in
			// the output from the python script.
			return true, nil
		case "error":
			// If there is any error from python script then we will
			// return the error message to the user.

			return true, fmt.Errorf("Error message from Python Script : %s", out.Message)
		case "output":
			// If the message is output then we need to read the output
			// from the python script and pass that to next step so we
			// will return false as we need to read the output not skip it.
			return false, nil
		}

		// If the message is not log, error or output then we need to skip
		// that message.
		return true, nil
	})

	// WaitMethod defines till how long cmdProcessor should wait before
	// considering the command as started.
	//
	// In this case we will wait till we get the message "Successfully loaded model"
	// from the python script. Once we get that message we will consider the command
	// as started and will pass the input to python script.
	u.cmdProcessor.SetWaitMethod(func(s string) (bool, error) {

		var out pythonResponse
		err := json.Unmarshal([]byte(s), &out)
		if err != nil {
			return false, fmt.Errorf("Failed to unmarshal the output (%s) wait method from python script: %v", s, err)
		}

		switch out.Type {
		case "log":
			return out.Message != "Successfully loaded model", nil
		case "error":
			// If there is any error from python script then we will
			// return the error message to the user.

			return false, fmt.Errorf("Python script is not stated because of error : %s", out.Message)
		case "output":
			// If we get any output in waiting state then we will consider
			// that as error because we are not expecting any output in waiting
			// state.
			return false, fmt.Errorf("in wait mode we should not get output")
		}

		return true, nil
	})

	// Start the command processor to execute the python script.
	// This will start the python3 python/spacy_runner.py command and
	// waits for the message "Successfully loaded model". Once that
	// is done we can pass continue input to python script and get
	// the PII labels related to the input.
	if err := u.cmdProcessor.Start(context.TODO()); err != nil {
		return fmt.Errorf("Failed to start the python script: %v", err)
	}

	return nil
}

// detectWorkingDir detects the working directory where the python script is located.
func (u *spacyDetector) detectWorkingDir() (string, error) {
	for _, w := range u.workDirs {
		// check if file is available or not
		if _, err := os.Stat(filepath.Join(w, spacyFileName)); err != nil {
			continue
		}
		return w, nil
	}

	return "", fmt.Errorf("spacy file not found in any location " + strings.Join(u.workDirs, ","))
}

// Detect detects the PII labels from the input word.
// spacyDetector is value detector so here work is considered
// as value.
//
// This will pass the input word to python script and get the
// PII labels related to the input.
func (u *spacyDetector) Detect(ctx context.Context, word string) ([]PiiLabelWithWeight, error) {

	// Process the input word and get the PII labels related to the input.
	// This will pass the input word to python script and get the PII labels
	// related to the input.
	out, err := u.cmdProcessor.Process(word)
	if err != nil {
		return nil, fmt.Errorf("failed to process input: %v", err)
	}

	// here response string is expected in pythonResponse format
	// so we will unmarshal the response string to pythonResponse
	// format and type is also expected as "output" only.
	var resp pythonResponse
	err = json.Unmarshal([]byte(out), &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if len(resp.Data.Entities) == 0 {
		return nil, nil
	}

	// From output we are expecting one entity only as we are passing
	// only one word to the python script.
	//
	// And also we are supporting only two labels "PERSON" and "GPE".
	// If we get any other label then we will ignore that and return
	// empty string.
	var labels []PiiLabelWithWeight
	for _, entity := range resp.Data.Entities {
		switch entity.Label {
		case "PERSON":
			labels = append(labels, PiiLabelWithWeight{
				PIILabel: PIILabel_Name,
				Weight:   0.3,
			})
		case "GPE":
			labels = append(labels, PiiLabelWithWeight{
				PIILabel: PIILabel_Address,
				Weight:   0.3,
			})
			// case "DATE":
			// 	labels = append(labels, PIILabel_BirthDate)
		}
	}

	return labels, nil
}
