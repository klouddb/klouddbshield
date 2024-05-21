package model

import (
	"fmt"
)

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
	FailReason     interface{}            `json:"FailReason"`
	Status         string                 `json:"Status"`
	Description    string                 `json:"Description"`
	Control        string                 `json:"Control"`
	Title          string                 `json:"Title"`
	Rationale      string                 `json:"Rationale"`
	References     string                 `json:"References"`
	Procedure      string                 `json:"Procedure"`
	CaseFailReason map[string]*CaseResult `json:"CaseFailReason"`
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
