package piiscanner

import (
	"context"
	"testing"

	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

func TestDPDPAIndiaDetectorsViaFactory(t *testing.T) {
	tests := []struct {
		name    string
		column  string
		value   string
		wantCol PIILabel
		wantVal PIILabel
		needCtx bool
	}{
		{
			name:    "PAN column and value",
			column:  "pan_number",
			value:   "ABCBE1234F",
			wantCol: PIILabel_PANNumber,
			wantVal: PIILabel_PANNumber,
		},
		{
			name:    "cheque requires column context",
			column:  "cheque_number",
			value:   "123456",
			wantCol: PIILabel_ChequeNumber,
			wantVal: PIILabel_ChequeNumber,
			needCtx: true,
		},
	}

	col := NewRegexColumnDetectorForRegion(RegionIndia)
	val := NewRegexValueDetectorForRegion(RegionIndia)
	if err := col.Init(); err != nil {
		t.Fatalf("init column: %v", err)
	}
	if err := val.Init(); err != nil {
		t.Fatalf("init value: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			colLabels, err := col.Detect(context.Background(), tt.column, nil)
			if err != nil {
				t.Fatalf("column detect: %v", err)
			}
			if !containsPIILabel(colLabels, tt.wantCol) {
				t.Fatalf("column labels %v missing %q", colLabels, tt.wantCol)
			}

			ctx := ColumnContext{}
			if tt.needCtx {
				for _, l := range colLabels {
					ctx[l.PIILabel] = true
				}
			}
			valLabels, err := val.Detect(context.Background(), tt.value, ctx)
			if err != nil {
				t.Fatalf("value detect: %v", err)
			}
			if !containsPIILabel(valLabels, tt.wantVal) {
				t.Fatalf("value labels %v missing %q", valLabels, tt.wantVal)
			}

			if tt.needCtx {
				without, err := val.Detect(context.Background(), tt.value, nil)
				if err != nil {
					t.Fatalf("value detect without context: %v", err)
				}
				if containsPIILabel(without, tt.wantVal) {
					t.Fatalf("expected no %q without column context, got %v", tt.wantVal, without)
				}
			}
		})
	}
}

func TestDPDPAWeightMergeLabels(t *testing.T) {
	set := WeightMergeEntities(RegionIndia)
	if !set.Contains(PIILabel_PANNumber) {
		t.Fatal("expected PANNumber in India weight-merge set from DPDPA")
	}
	if set.Contains(PIILabel_Email) {
		t.Fatal("did not expect Email in India weight-merge set")
	}
	// Ensure factory returns DPDPA constructors (smoke).
	_ = dpdpa.NewIndiaColumnDetector()
	_ = dpdpa.NewIndiaValueDetector()
}
