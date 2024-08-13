package queryparser

import (
	"fmt"

	"github.com/xwb1989/sqlparser"
)

func ParseSelectStmt(stmt sqlparser.SelectStatement) (*KVPairs, error) {
	switch stmt := stmt.(type) {
	case *sqlparser.Select:
		if stmt == nil {
			return nil, nil
		}

		exprs := []sqlparser.Expr{}
		if stmt.Where != nil {
			exprs = append(exprs, stmt.Where.Expr)
		}

		if stmt.Having != nil {
			exprs = append(exprs, stmt.Having.Expr)
		}

		return ParseExprs(exprs...)
	}

	return nil, nil
}

func ParserDeleteStmt(stmt *sqlparser.Delete) (*KVPairs, error) {
	if stmt == nil || stmt.Where == nil {
		return nil, nil
	}

	return ParseExpr(stmt.Where.Expr)
}

func ParserUpdateStmt(stmt *sqlparser.Update) (*KVPairs, error) {
	if stmt == nil {
		return nil, nil
	}

	out := NewKVPairs()

	for _, expr := range stmt.Exprs {
		if expr == nil {
			continue
		}

		out.Add(expr.Name.Name.String(), getVal(expr.Expr))

		pair, err := ParseExpr(expr.Expr)
		if err != nil {
			return nil, err
		}
		out.Merge(pair)
	}

	whereResp, err := ParseExpr(stmt.Where.Expr)
	return out.Merge(whereResp), err
}

func ParserInsertStmt(stmt *sqlparser.Insert) (*KVPairs, error) {
	if stmt == nil || stmt.Rows == nil || len(stmt.Columns) == 0 {
		return nil, nil
	}

	out := NewKVPairs()

	rows, ok := stmt.Rows.(sqlparser.Values)
	if !ok {
		return nil, fmt.Errorf("invalid row type")
	}

	for _, row := range rows {
		if len(row) != len(stmt.Columns) {
			return nil, fmt.Errorf("invalid row length")
		}

		for idx, expr := range row {
			out.Add(stmt.Columns[idx].String(), getVal(expr))
		}
	}

	return out, nil
}
