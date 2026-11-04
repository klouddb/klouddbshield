package piiscanner

import (
	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

// Re-export DPDPA label/detector types so shared APIs stay owned by one package.
// New India entities added in DPDPA appear here after a module bump.
type (
	PIILabel           = dpdpa.PIILabel
	ColumnContext      = dpdpa.ColumnContext
	PiiLabelWithWeight = dpdpa.PiiLabelWithWeight
	Detector           = dpdpa.Detector
)

const (
	RegionIndia = dpdpa.RegionIndia

	PIILabel_Name        = dpdpa.PIILabel_Name
	PIILabel_Email       = dpdpa.PIILabel_Email
	PIILabel_Phone       = dpdpa.PIILabel_Phone
	PIILabel_Address     = dpdpa.PIILabel_Address
	PIILabel_BirthDate   = dpdpa.PIILabel_BirthDate
	PIILabel_CreditCard  = dpdpa.PIILabel_CreditCard
	PIILabel_Password    = dpdpa.PIILabel_Password
	PIILabel_IPAddress   = dpdpa.PIILabel_IPAddress
	PIILabel_MacAddress  = dpdpa.PIILabel_MacAddress
	PIILabel_OAuthToken  = dpdpa.PIILabel_OAuthToken
	PIILabel_Location    = dpdpa.PIILabel_Location
	PIILabel_Nationality = dpdpa.PIILabel_Nationality
	PIILabel_Gender      = dpdpa.PIILabel_Gender
	PIILabel_Username    = dpdpa.PIILabel_Username

	PIILabel_UPIID                 = dpdpa.PIILabel_UPIID
	PIILabel_CVV                   = dpdpa.PIILabel_CVV
	PIILabel_TAN                   = dpdpa.PIILabel_TAN
	PIILabel_CIN                   = dpdpa.PIILabel_CIN
	PIILabel_MICRCode              = dpdpa.PIILabel_MICRCode
	PIILabel_ABHANumber            = dpdpa.PIILabel_ABHANumber
	PIILabel_UAN                   = dpdpa.PIILabel_UAN
	PIILabel_EPFMemberID           = dpdpa.PIILabel_EPFMemberID
	PIILabel_BankAccountNumber     = dpdpa.PIILabel_BankAccountNumber
	PIILabel_DematAccountNumber    = dpdpa.PIILabel_DematAccountNumber
	PIILabel_PANNumber             = dpdpa.PIILabel_PANNumber
	PIILabel_AdharcardNumber       = dpdpa.PIILabel_AdharcardNumber
	PIILabel_DrivingLicenceNumber  = dpdpa.PIILabel_DrivingLicenceNumber
	PIILabel_GSTIN                 = dpdpa.PIILabel_GSTIN
	PIILabel_ChequeNumber          = dpdpa.PIILabel_ChequeNumber
	PIILabel_CIFNumber             = dpdpa.PIILabel_CIFNumber
	PIILabel_LoanAccountNumber     = dpdpa.PIILabel_LoanAccountNumber
	PIILabel_InsurancePolicyNumber = dpdpa.PIILabel_InsurancePolicyNumber
	PIILabel_FASTagID              = dpdpa.PIILabel_FASTagID
	PIILabel_VehicleNumber         = dpdpa.PIILabel_VehicleNumber
	PIILabel_VoterID               = dpdpa.PIILabel_VoterID
	PIILabel_PassportNumber        = dpdpa.PIILabel_PassportNumber
	PIILabel_IFSC                  = dpdpa.PIILabel_IFSC
	PIILabel_ESIC                  = dpdpa.PIILabel_ESIC
	PIILabel_RationCard            = dpdpa.PIILabel_RationCard
	PIILabel_SEBIRegistration      = dpdpa.PIILabel_SEBIRegistration
)

// Legacy-only labels used by the empty-region (non-India) detector pack.
// These are not defined in DPDPA.
const (
	PIILabel_SSN       PIILabel = "SSN"
	PIILabel_PoBox     PIILabel = "PoBox"
	PIILabel_ZipCode   PIILabel = "ZipCode"
	PIILabel_ITIN      PIILabel = "ITIN"
	PIILabel_NHSNumber PIILabel = "NHSNumber"
)

// IsIndiaRegion reports whether region selects the India/DPDPA detector path.
func IsIndiaRegion(region string) bool {
	return dpdpa.IsIndiaRegion(region)
}
