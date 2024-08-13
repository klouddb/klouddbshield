package piiscanner

import (
	"context"
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"testing"
)

//go:embed MOCK_DATA.csv
var mockData embed.FS

func TestSpacyDetector(t *testing.T) {
	spacyDetector := NewSpacyDetector().WithWorkDirs([]string{"../../python"})
	if spacyDetector == nil {
		t.Errorf("SpacyDetector is nil")
	}

	err := spacyDetector.Init()
	if err != nil {
		t.Errorf("SpacyDetector init failed %v", err)
		return
	}

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
		piiLabel, err := spacyDetector.Detect(context.TODO(), input)
		if err != nil {
			t.Errorf("Error while processing input %v", err)
			return
		}

		fmt.Println("pii label", piiLabel)
	}

}

func SpacyLabelTestHelper(t *testing.T, inputs *[]string, label PIILabel) {
	spacyDetector := NewSpacyDetector().WithWorkDirs([]string{"../../python"})
	if spacyDetector == nil {
		t.Errorf("SpacyDetector is nil")
	}

	err := spacyDetector.Init()
	if err != nil {
		t.Errorf("SpacyDetector init failed %v", err)
		return
	}

	for _, input := range *inputs {
		piiLabel, err := spacyDetector.Detect(context.TODO(), input)
		if err != nil {
			t.Errorf("Error while processing input %v", err)
			return
		}

		if NewPiiLabelMapFromPiiLableWithWeight("regex", piiLabel).GetMax() != label {
			t.Errorf("for input %s, expected %v, got %v", input, label, piiLabel)
			return
		}
	}
}

func SpacyLabelTestPercentageHelper(t *testing.T, inputs *[]string, label PIILabel) {
	spacyDetector := NewSpacyDetector().WithWorkDirs([]string{"../../python"})
	if spacyDetector == nil {
		t.Errorf("SpacyDetector is nil")
	}

	err := spacyDetector.Init()
	if err != nil {
		t.Errorf("SpacyDetector init failed %v", err)
		return
	}

	num_correct := 0
	for _, input := range *inputs {
		piiLabel, err := spacyDetector.Detect(context.TODO(), input)
		if err != nil {
			t.Errorf("Error while processing input %v", err)
			return
		}

		if NewPiiLabelMapFromPiiLableWithWeight("regex", piiLabel).GetMax() == label {
			num_correct++
		} else {
			t.Logf("for input %s, expected %v, got %v", input, label, piiLabel)
		}
	}

	total_values := len(*inputs)
	percentage := float32(num_correct) / float32(total_values) * 100
	if percentage == 100 {
		t.Logf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	} else {
		t.Errorf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	}
}

func SpacyLabelTestPercentageFromCSVHelper(t *testing.T, col_name string, label PIILabel) {
	// Initialize spacy detector
	spacyDetector := NewSpacyDetector().WithWorkDirs([]string{"../../python"})
	if spacyDetector == nil {
		t.Fatalf("SpacyDetector is nil")
	}

	err := spacyDetector.Init()
	if err != nil {
		t.Fatalf("SpacyDetector init failed %v", err)
	}

	// Open file
	file, err := mockData.Open("MOCK_DATA.csv")
	if err != nil {
		t.Fatalf("Error while opening the file %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Read header
	header, err := reader.Read()
	if err != nil {
		t.Fatalf("Error while reading the file %v", err)
	}

	// Look for column name in header
	i := -1
	for a, item := range header {
		if item == col_name {
			i = a
			break
		}
	}

	if i == -1 {
		t.Fatalf("Column name not found")
	}

	// Process each record
	num_correct := 0
	total_values := 0
	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("Error while reading the file %v", err)
		}
		total_values++

		// Check label detection
		input := record[i]
		piiLabel, err := spacyDetector.Detect(context.TODO(), input)
		if err != nil {
			t.Fatalf("Error while processing input %v", err)
		}

		if NewPiiLabelMapFromPiiLableWithWeight("regex", piiLabel).GetMax() == label {
			num_correct++
		} else {
			t.Logf("for input %s, expected %v, got %v", input, label, piiLabel)
		}
	}

	percentage := float32(num_correct) / float32(total_values) * 100
	if percentage == 100 {
		t.Logf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	} else {
		t.Errorf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	}
}

func SpacyFullNameTestPercentageFromCSVHelper(t *testing.T) {
	// Initialize spacy detector
	spacyDetector := NewSpacyDetector().WithWorkDirs([]string{"../../python"})
	if spacyDetector == nil {
		t.Fatalf("SpacyDetector is nil")
	}

	err := spacyDetector.Init()
	if err != nil {
		t.Fatalf("SpacyDetector init failed %v", err)
	}

	// Open file
	file, err := mockData.Open("MOCK_DATA.csv")
	if err != nil {
		t.Fatalf("Error while opening the file %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Read header
	header, err := reader.Read()
	if err != nil {
		t.Fatalf("Error while reading the file %v", err)
	}

	// Look for column name in header
	i1 := -1
	i2 := -1
	for a, item := range header {
		if i1 == -1 && item == "first_name" {
			i1 = a
		}
		if i2 == -1 && item == "last_name" {
			i2 = a
		}

		if i1 != -1 && i2 != -1 {
			break
		}
	}

	if i1 == -1 {
		t.Fatalf("First name column not found")
	}
	if i2 == -1 {
		t.Fatalf("Last name column not found")
	}

	// Process each record
	num_correct := 0
	total_values := 0
	label := PIILabel_Name
	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("Error while reading the file %v", err)
		}
		total_values++

		// Check label detection
		input := record[i1] + " " + record[i2]
		piiLabel, err := spacyDetector.Detect(context.TODO(), input)
		if err != nil {
			t.Fatalf("Error while processing input %v", err)
		}

		if NewPiiLabelMapFromPiiLableWithWeight("regex", piiLabel).GetMax() == label {
			num_correct++
		} else {
			t.Logf("for input %s, expected %v, got %v", input, label, piiLabel)
		}
	}

	percentage := float32(num_correct) / float32(total_values) * 100
	if percentage == 100 {
		t.Logf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	} else {
		t.Errorf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	}
}

// Data from https://playground.nightfall.ai/data
func TestName(t *testing.T) {
	inputs := []string{
		"pradip",
		"Pradip",
		"kevin",
		"Kevin",
		"Kelly Carroll",
		"Kelly",
		"Carroll",
		"Vincent Rau",
		"Vincent",
		"Rau",
		"Jerry Kreiger",
		"Jerry",
		"Kreiger",
		"Lara Klocko",
		"Lara",
		"Klocko",
		"Mara Renner",
		"Mara",
		"Renner",
		"Jon Schamberger",
		"Jon",
		"Schamberger",
		"Rogelio Fahey",
		"Rogelio",
		"Fahey",
		"Eugenio Adams",
		"Eugenio",
		"Adams",
		"Ms. Hassie Larkin",
		"Hassie",
		"Larkin",
		"Stacy Rice",
		"Stacy",
		"Rice",
		"Lyle Stroman",
		"Lyle",
		"Stroman",
		"Brendan Lakin PhD",
		"Brendan",
		"Lakin",
		"Mollie Greenfelder",
		"Mollie",
		"Greenfelder",
		"Daron Zemlak",
		"Daron",
		"Zemlak",
		"Glendora Funk Sr.",
		"Glendora",
		"Funk",
		"Brooks Stracke",
		"Brooks",
		"Stracke",
		"Chi Sporer",
		"Chi",
		"Sporer",
		"Mirian Hamill",
		"Mirian",
		"Hamill",
		"Tu Mayert",
		"Tu",
		"Mayert",
		"Rosana Collier",
		"Rosana",
		"Collier",
		// "Chuck",
		// "Alesha",
		// "Devin",
		// "Cherie",
		// "Floria",
		// "Goldner",
		// "Lowe",
		// "Spencer",
		// "Russel",
		// "O'Connell",
		// "Smith",
		// "McLaughlin",
		// "Sanford",
		// "Stark",
		// "Harris",
	}

	SpacyLabelTestHelper(t, &inputs, PIILabel_Name)
}

func TestNamePercentage(t *testing.T) {
	inputs := []string{
		// "pradip",
		// "Pradip",
		// "kevin",
		// "Kevin",
		// "Kelly Carroll",
		// "Vincent Rau",
		// "Jerry Kreiger",
		// "Lara Klocko",
		// "Mara Renner",
		// "Jon Schamberger",
		// "Rogelio Fahey",
		// "Eugenio Adams",
		// "Ms. Hassie Larkin",
		// "Stacy Rice",
		// "Lyle Stroman",
		// "Brendan Lakin PhD",
		// "Mollie Greenfelder",
		// "Daron Zemlak",
		// "Glendora Funk Sr.",
		// "Brooks Stracke",
		// "Chi Sporer",
		// "Mirian Hamill",
		// "Tu Mayert",
		// "Rosana Collier",
		"Kelly", // start of separation
		"Carroll",
		"Vincent",
		"Rau",
		"Jerry",
		"Kreiger",
		"Lara",
		"Klocko",
		"Mara",
		"Renner",
		"Jon",
		"Schamberger",
		"Rogelio",
		"Fahey",
		"Eugenio",
		"Adams",
		"Hassie",
		"Larkin",
		"Stacy",
		"Rice",
		"Lyle",
		"Stroman",
		"Brendan",
		"Lakin",
		"Mollie",
		"Greenfelder",
		"Daron",
		"Zemlak",
		"Glendora",
		"Funk",
		"Brooks",
		"Stracke",
		"Chi",
		"Sporer",
		"Mirian",
		"Hamill",
		"Tu",
		"Mayert",
		"Rosana",
		"Collier", // end of separation
		// "Chuck",
		// "Alesha",
		// "Devin",
		// "Cherie",
		// "Floria",
		// "Goldner",
		// "Lowe",
		// "Spencer",
		// "Russel",
		// "O'Connell",
		// "Smith",
		// "McLaughlin",
		// "Sanford",
		// "Stark",
		// "Harris",
	}

	SpacyLabelTestPercentageHelper(t, &inputs, PIILabel_Name)
}

// CSV data from https://www.mockaroo.com/
func TestFirstNameCSV(t *testing.T) {
	col_name := "first_name"
	label := PIILabel_Name
	SpacyLabelTestPercentageFromCSVHelper(t, col_name, label)
}

// CSV data from https://www.mockaroo.com/
func TestLastNameCSV(t *testing.T) {
	col_name := "last_name"
	label := PIILabel_Name
	SpacyLabelTestPercentageFromCSVHelper(t, col_name, label)
}

// CSV data from https://www.mockaroo.com/
func TestFullNameCSV(t *testing.T) {
	SpacyFullNameTestPercentageFromCSVHelper(t)
}

func TestAddress(t *testing.T) {
	inputs := []string{
		"600 32nd Ave, San Francisco, CA 94121",
		"3500 Fillmore St, San Francisco, CA 94123",
	}

	SpacyLabelTestHelper(t, &inputs, PIILabel_Address)
}

func TestAddressPercentage(t *testing.T) {
	inputs := []string{
		"600 32nd Ave, San Francisco, CA 94121",
		"3500 Fillmore St, San Francisco, CA 94123",
	}

	SpacyLabelTestPercentageHelper(t, &inputs, PIILabel_Address)
}
