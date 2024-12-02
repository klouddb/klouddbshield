package model

import (
	"context"
	"fmt"
)

func NewContextWithVersion(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, "version", version) //nolint:staticcheck
}

func GetVersionFromContext(ctx context.Context) string {
	ver := ctx.Value("version")
	if ver == nil {
		return ""
	}

	return ver.(string)
}

func IsFromVersion(ctx context.Context, versions []string) bool {
	ver := GetVersionFromContext(ctx)
	for _, v := range versions {
		if ver == v {
			return true
		}
	}

	return false
}

type CaseResult struct {
	Name   string
	Reason string
	Status string
}

func NewCaseResult(name string) *CaseResult {
	return &CaseResult{
		Name:   name,
		Status: "Fail",
		Reason: fmt.Sprintf("no subscription found for %s", name),
	}
}

// type Result struct {
// 	FailReason     interface{} `json:"FailReason,omitempty"`
// 	Status         string
// 	Description    string `json:"-"`
// 	Control        string
// 	Title          string
// 	Rationale      string `json:"-"`
// 	References     string `json:"-"`
// 	Procedure      string `json:"-"`
// 	CaseFailReason map[string]*CaseResult
// }

type Result struct {
	FailReason      string                 `json:"FailReason"`
	Status          string                 `json:"Status"`
	Description     string                 `json:"Description"`
	Control         string                 `json:"Control"`
	Title           string                 `json:"Title"`
	Rationale       string                 `json:"Rationale"`
	References      string                 `json:"References"`
	Procedure       string                 `json:"Procedure"`
	CaseFailReason  map[string]*CaseResult `json:"CaseFailReason"`
	ManualCheckData ManualCheckData        `json:"ManualCheckData"`
	Critical        bool                   `json:"Critical"`
	// ReferenceLink   string                 `json:"ReferenceLink"`
}

type Config struct {
	DbHostname string
	Results    []*Result
}
type CustomError struct {
	Status  bool   `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type Status struct {
	Pass int
	Fail int
}

type ConfigAuditResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	FailReason string `json:"fail_reason"`
}

type SSLScanResult struct {
	Cells []*SSLScanResultCell `json:"cells"`

	HBALines  []string          `json:"hba_lines"`
	SSLParams map[string]string `json:"ssl_params"`
}

type SSLScanResultCell struct {
	Title   string `json:"title"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type HBAScannerResult struct {
	Title            string
	Control          int
	Description      string
	Procedure        string
	Status           string
	FailRowsLineNums []int    `json:"-"`
	FailRows         []string `json:"FailRows,omitempty"`
	FailRowsInString string   `json:"-"`
}

type DataTable struct {
	Title    string
	Columns  []string
	ColAlias []string
	Rows     [][]interface{}
	Error    error
}

type Section struct {
	Name     string
	Score    int
	MaxScore int
	Color    string
}

type UserlistResult struct {
	Title string
	Data  ManualCheckData
}
