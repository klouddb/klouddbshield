package logparser

import (
	"context"

	"github.com/klouddb/klouddbshield/pkg/parselog"
)

type ResultCalculator interface {
	CalculateResult(ctx context.Context) error
}

type ErrorHelper struct {
	Command string
	Status  string
	Message string
}

func NewErrorHelper(command, status, message string) *ErrorHelper {
	return &ErrorHelper{
		Status:  status,
		Message: message,
	}
}

func (d *ErrorHelper) Feed(parsedData parselog.ParsedData) error {
	return nil
}
