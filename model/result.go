package model

import (
	"database/sql"
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

type Result struct {
	FailReason     interface{} `json:"FailReason,omitempty"`
	Status         string
	Description    string `json:"-"`
	Control        string
	Title          string
	Rationale      string `json:"-"`
	References     string `json:"-"`
	Procedure      string `json:"-"`
	CaseFailReason map[string]*CaseResult
}
type Config struct {
	store      *sql.DB
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
