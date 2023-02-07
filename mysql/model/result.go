package model

import "database/sql"

type Result struct {
	FailReason  interface{} `json:"FailReason,omitempty"`
	Procedure   string      `json:",omitempty"`
	Status      string
	Description string
	Control     string
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
