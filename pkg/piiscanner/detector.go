package piiscanner

import "context"

type PIILabel string

const (
	PIILabel_Name        PIILabel = "Name"
	PIILabel_Email       PIILabel = "Email"
	PIILabel_Phone       PIILabel = "Phone"
	PIILabel_Address     PIILabel = "Address"
	PIILabel_BirthDate   PIILabel = "BirthDate"
	PIILabel_CreditCard  PIILabel = "CreditCard"
	PIILabel_SSN         PIILabel = "SSN"
	PIILabel_PoBox       PIILabel = "PoBox"
	PIILabel_Password    PIILabel = "Password"
	PIILabel_ZipCode     PIILabel = "ZipCode"
	PIILabel_IPAddress   PIILabel = "IPAddress"
	PIILabel_MacAddress  PIILabel = "MacAddress"
	PIILabel_OAuthToken  PIILabel = "OAuthToken"
	PIILabel_Location    PIILabel = "Location"
	PIILabel_Nationality PIILabel = "Nationality"
	PIILabel_Gender      PIILabel = "Gender"
	PIILabel_Username    PIILabel = "Username"

	// PIILabel_BankAccountNumber is pii label for bank account number.
	// currently we are only supporting for india and USA.
	// for this we only have column regex.
	PIILabel_BankAccountNumber PIILabel = "BankAccountNumber"

	// PIILabel_PANNumber is pii label for PAN number.
	// currently we are only supporting for india. for this we have column and value regex.
	PIILabel_PANNumber PIILabel = "PANNumber"

	// PIILabel_AdharcardNumber is pii label for Adharcard number.
	// currently we are only supporting for india. for this we have column regex only.
	// value regexs are clash with phone number.
	PIILabel_AdharcardNumber PIILabel = "AdharcardNumber"

	// PIILabel_ITIN is pii label for ITIN number for USA.
	// itin column names are clashing with PIILabel_PANNumber so for now only adding value checks.
	PIILabel_ITIN PIILabel = "ITIN"

	// PIILabel_DrivingLicenceNumber is pii label for Driving Licence number.
	// currently we are only supporting for india. for this we have column and value regex both for india
	PIILabel_DrivingLicenceNumber PIILabel = "DrivingLicenceNumber"

	PIILabel_NHSNumber PIILabel = "NHSNumber"

	// PIILabel_GSTIN is pii label for GSTIN number.
	PIILabel_GSTIN PIILabel = "GSTIN"

	// PIILabel_VehicleNumber is pii label for Vehicle number.
	// currently we have only value regex for india.
	PIILabel_VehicleNumber PIILabel = "VehicleNumber"

	// PIILabel_VoterID is pii label for Voter ID.
	// currently we have only value regex for india.
	PIILabel_VoterID PIILabel = "VoterID"
)

// Detector is an interface that defines the methods that a PII detector should implement.
// - The Init method is used to initialize the detector.
// - The Detect method is used to detect the PII data in the given word.
//
// Detector can be of two types:
// - ValueDetector: Detects the PII data in the value.
// - ColumnDetector: Detects the PII data in the column.
// The ValueDetector and ColumnDetector are used to detect the PII data in the value and column respectively.
type Detector interface {
	Name() string

	// Init is a function that triggers initialization of the detector.
	Init() error

	// Detect is a function that takes a word as input and detects the PII data in the word.
	// if it is ValueDetector, then the word in input will be considered as value from query.
	// if it is ColumnDetector, then the word in input will be considered as column from query.
	//
	// e.g
	// 		Query: SELECT name, email FROM users WHERE name = 'John Doe' AND email = 'somethig@gmail.com';
	// 		Word: 'name' is column and 'John Doe' is value.
	// 		Word: 'email' is column and 'something@gmail.com' is value.
	Detect(ctx context.Context, word string) ([]PiiLabelWithWeight, error)
}

type PiiLabelWithWeight struct {
	PIILabel PIILabel
	Weight   float64
}
