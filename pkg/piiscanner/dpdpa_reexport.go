package piiscanner

import (
	dpdpa "github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

// Re-export shared types from DPDPA so this package does not maintain a second copy.
type (
	TableScanManager        = dpdpa.TableScanManager
	TableScannerOutput      = dpdpa.TableScannerOutput
	PiiData                 = dpdpa.PiiData
	PiiLabelMap             = dpdpa.PiiLabelMap
	WeightWithCount         = dpdpa.WeightWithCount
	ScanInput               = dpdpa.ScanInput
	ScanOutput              = dpdpa.ScanOutput
	TableScanWorker         = dpdpa.TableScanWorker
	SpacyDetector           = dpdpa.SpacyDetector
	DatabasePIIScanOutput   = dpdpa.DatabasePIIScanOutput
	TableDetailOutput       = dpdpa.TableDetailOutput
	PIIDataWithWeightString = dpdpa.PIIDataWithWeightString
	DetectorType            = dpdpa.DetectorType
	OutputOptions           = dpdpa.OutputOptions
	RunOption               = dpdpa.RunOption
	RegexWithWeight         = dpdpa.RegexWithWeight
)

const (
	DetectorType_ColumnDetector = dpdpa.DetectorType_ColumnDetector
	DetectorType_ValueDetector  = dpdpa.DetectorType_ValueDetector

	RunOption_MetaScan  = dpdpa.RunOption_MetaScan
	RunOption_DataScan  = dpdpa.RunOption_DataScan
	RunOption_DeepScan  = dpdpa.RunOption_DeepScan
	RunOption_SpacyScan = dpdpa.RunOption_SpacyScan

	RunOption_MetaScan_String  = dpdpa.RunOption_MetaScan_String
	RunOption_DataScan_String  = dpdpa.RunOption_DataScan_String
	RunOption_DeepScan_String  = dpdpa.RunOption_DeepScan_String
	RunOption_SpacyScan_String = dpdpa.RunOption_SpacyScan_String

	RunOption_MetaScan_Title  = dpdpa.RunOption_MetaScan_Title
	RunOption_DataScan_Title  = dpdpa.RunOption_DataScan_Title
	RunOption_DeepScan_Title  = dpdpa.RunOption_DeepScan_Title
	RunOption_SpacyScan_Title = dpdpa.RunOption_SpacyScan_Title

	DEEPSCAN_WARNINING_LIMIT     = dpdpa.DEEPSCAN_WARNINING_LIMIT
	DEEPSCAN_SPACY_WARNING_LIMIT = dpdpa.DEEPSCAN_SPACY_WARNING_LIMIT
)

var (
	NewTableScanManager        = dpdpa.NewTableScanManager
	NewPiiLabelMap             = dpdpa.NewPiiLabelMap
	NewTableScanWorker         = dpdpa.NewTableScanWorker
	NewSpacyDetector           = dpdpa.NewSpacyDetector
	NewPIIDataWithWeightString = dpdpa.NewPIIDataWithWeightString
	LuhnValid                  = dpdpa.LuhnValid
	RunOptionSlice             = dpdpa.RunOptionSlice
	IsValidRunOption           = dpdpa.IsValidRunOption
	OrderMap                   = dpdpa.OrderMap
	RunOptionMap               = dpdpa.RunOptionMap
	RunOptionTitleMap          = dpdpa.RunOptionTitleMap
	SpacyWorkDirs              = dpdpa.SpacyWorkDirs
	MergeLegacyValueWeight     = dpdpa.MergeLegacyValueWeight
	SortColumnFindings         = dpdpa.SortColumnFindings
)
