package model

import "database/sql"

type Result struct {
	FailReason  interface{} `json:"FailReason,omitempty"`
	Status      string
	Description string `json:"-"`
	Control     string
	Title       string
	Rationale   string `json:"-"`
	References  string `json:"-"`
	Procedure   string `json:"-"`
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
