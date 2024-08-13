package queryparser

import (
	"fmt"
	"strings"

	"github.com/xwb1989/sqlparser"
)

func GetQueryFromMessage(msg string) (string, bool) {
	msg = strings.TrimSpace(msg)
	if !strings.HasPrefix(msg, "statement:") {
		return "", false
	}

	msg = strings.TrimPrefix(msg, "statement:")
	msg = strings.TrimSpace(msg)
	if strings.HasPrefix(msg, "select") || strings.HasPrefix(msg, "SELECT") ||
		strings.HasPrefix(msg, "update") || strings.HasPrefix(msg, "UPDATE") ||
		strings.HasPrefix(msg, "delete") || strings.HasPrefix(msg, "DELETE") ||
		strings.HasPrefix(msg, "insert") || strings.HasPrefix(msg, "INSERT") {
		return msg, true
	}

	return "", false
}

func ParseSqlQuery(sql string) (*KVPairs, error) {

	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		return nil, err
	}

	// Otherwise do something with stmt
	switch stmt := stmt.(type) {
	case *sqlparser.Select:
		return ParseSelectStmt(stmt)
	case *sqlparser.Update:
		return ParserUpdateStmt(stmt)
	case *sqlparser.Delete:
		return ParserDeleteStmt(stmt)
	case *sqlparser.Insert:
		return ParserInsertStmt(stmt)
	default:
		fmt.Printf("%#v string is '%s'\n", stmt, sql)
		fmt.Println("Unknown")
	}

	return nil, nil
}
