package rds

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTablePrinter(t *testing.T) {
	tp := NewTablePrinter()
	tp.AddInstance("db1", "Pass", "true")
	tp.AddInstance("db2", "Fail", "false")
	assert.Equal(t, tp.Print(), "Instance\tStatus\tCurrent Value\t\ndb1\tPass\ttrue\t\ndb2\tFail\tfalse\t\n")
}
