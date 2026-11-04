package piiscanner

import (
	"context"
	"testing"
)

func TestRegexDetectorRegionAndCreditCard(t *testing.T) {
	columnDetector := NewRegexColumnDetector()
	valueDetector := NewRegexValueDetector()
	indiaValueDetector := NewRegexValueDetectorForRegion(RegionIndia)
	indiaColumnDetector := NewRegexColumnDetectorForRegion(RegionIndia)

	for name, detector := range map[string]Detector{
		"column":       columnDetector,
		"value":        valueDetector,
		"india value":  indiaValueDetector,
		"india column": indiaColumnDetector,
	} {
		if err := detector.Init(); err != nil {
			t.Fatalf("initialize %s detector: %v", name, err)
		}
	}

	tests := []struct {
		name     string
		detector Detector
		input    string
		context  ColumnContext
		want     PIILabel
		notWant  PIILabel
	}{
		{
			name:     "email column (legacy)",
			detector: columnDetector,
			input:    "email",
			want:     PIILabel_Email,
		},
		{
			name:     "PAN column still present in legacy",
			detector: columnDetector,
			input:    "pan_number",
			want:     PIILabel_PANNumber,
		},
		{
			name:     "email value (legacy)",
			detector: valueDetector,
			input:    "alice@example.com",
			want:     PIILabel_Email,
		},
		{
			name:     "PAN value still present in legacy",
			detector: valueDetector,
			input:    "ABCDE1234F",
			want:     PIILabel_PANNumber,
		},
		{
			name:     "legacy does not add new DPDPA entities (UPI)",
			detector: valueDetector,
			input:    "user@ybl",
			notWant:  PIILabel_UPIID,
		},
		{
			name:     "Luhn-valid credit card (legacy updated CC)",
			detector: valueDetector,
			input:    "378282246310005",
			want:     PIILabel_CreditCard,
		},
		{
			name:     "Luhn-invalid credit card rejected (legacy updated CC)",
			detector: valueDetector,
			input:    "378282246310006",
			notWant:  PIILabel_CreditCard,
		},
		{
			name:     "India region includes PAN",
			detector: indiaValueDetector,
			input:    "ABCBE1234F",
			want:     PIILabel_PANNumber,
		},
		{
			name:     "India region includes UPI",
			detector: indiaValueDetector,
			input:    "user@ybl",
			want:     PIILabel_UPIID,
		},
		{
			name:     "Verhoeff-invalid Aadhaar rejected in India mode",
			detector: indiaValueDetector,
			input:    "123456789012",
			notWant:  PIILabel_AdharcardNumber,
		},
		{
			name:     "context-required value with matching context (India)",
			detector: indiaValueDetector,
			input:    "123456",
			context:  ColumnContext{PIILabel_ChequeNumber: true},
			want:     PIILabel_ChequeNumber,
		},
		{
			name:     "context-required value without context (India)",
			detector: indiaValueDetector,
			input:    "123456",
			notWant:  PIILabel_ChequeNumber,
		},
		{
			name:     "IPv4 value (legacy)",
			detector: valueDetector,
			input:    "192.168.1.10",
			want:     PIILabel_IPAddress,
		},
		{
			name:     "MAC address value (legacy)",
			detector: valueDetector,
			input:    "00:1A:2B:3C:4D:5E",
			want:     PIILabel_MacAddress,
		},
		{
			name:     "plain text has no label",
			detector: valueDetector,
			input:    "ordinary product description",
			want:     "",
		},
		{
			name:     "SSN still in legacy",
			detector: valueDetector,
			input:    "123-45-6789",
			want:     PIILabel_SSN,
		},
		{
			name:     "SSN not in India pack",
			detector: indiaValueDetector,
			input:    "123-45-6789",
			notWant:  PIILabel_SSN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, err := tt.detector.Detect(context.Background(), tt.input, tt.context)
			if err != nil {
				t.Fatalf("detect %q: %v", tt.input, err)
			}
			if tt.want != "" && !containsPIILabel(labels, tt.want) {
				t.Fatalf("detect %q: labels %v do not contain %q", tt.input, labels, tt.want)
			}
			if tt.want == "" && tt.notWant == "" && len(labels) != 0 {
				t.Fatalf("detect %q: got unexpected labels %v", tt.input, labels)
			}
			if tt.notWant != "" && containsPIILabel(labels, tt.notWant) {
				t.Fatalf("detect %q: labels %v unexpectedly contain %q", tt.input, labels, tt.notWant)
			}
		})
	}
}

func containsPIILabel(labels []PiiLabelWithWeight, want PIILabel) bool {
	for _, label := range labels {
		if label.PIILabel == want {
			return true
		}
	}
	return false
}
