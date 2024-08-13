package queryparser

import (
	"github.com/xwb1989/sqlparser"
)

func ParseExprs(exprs ...sqlparser.Expr) (*KVPairs, error) {
	out := NewKVPairs()

	for _, expr := range exprs {
		pair, err := ParseExpr(expr)
		if err != nil {
			return nil, err
		}

		out.Merge(pair)
	}

	return out, nil
}

func ParseExpr(expr sqlparser.Expr) (*KVPairs, error) {

	switch expr := expr.(type) {
	case *sqlparser.AndExpr:
		return ParseExprs(expr.Left, expr.Right)
	case *sqlparser.OrExpr:
		return ParseExprs(expr.Left, expr.Right)
	case *sqlparser.NotExpr:
		return ParseExpr(expr.Expr)
	case *sqlparser.ParenExpr:
		return ParseExpr(expr.Expr)

	case *sqlparser.ComparisonExpr:
		out := NewKVPairs()
		out.Add(getColumnName(expr.Left), getVal(expr.Right))

		resp, err := ParseExprs(expr.Left, expr.Right)
		return out.Merge(resp), err

	case *sqlparser.RangeCond:
		out := NewKVPairs()
		columnName := getColumnName(expr.Left)
		out.Add(columnName, getVal(expr.From))
		out.Add(columnName, getVal(expr.To))

		resp, err := ParseExprs(expr.From, expr.To)
		return out.Merge(resp), err

	case *sqlparser.IsExpr:
		return ParseExpr(expr.Expr)

	case *sqlparser.ExistsExpr:
		return ParseExpr(expr.Subquery)

	case *sqlparser.Subquery:
		return ParseSelectStmt(expr.Select)

	case *sqlparser.BinaryExpr:
		return ParseExprs(expr.Left, expr.Right)
	case *sqlparser.UnaryExpr:
		return ParseExpr(expr.Expr)
	case *sqlparser.IntervalExpr:
		return ParseExpr(expr.Expr)
	case *sqlparser.CollateExpr:
		return ParseExpr(expr.Expr)

	case *sqlparser.CaseExpr:
		exprs := []sqlparser.Expr{expr.Expr, expr.Else}
		for _, when := range expr.Whens {
			exprs = append(exprs, when.Cond, when.Val)
		}

		return ParseExprs(exprs...)

	case *sqlparser.ConvertExpr:
		return ParseExpr(expr.Expr)
	case *sqlparser.SubstrExpr:
		return ParseExprs(expr.From, expr.To)

	case *sqlparser.ConvertUsingExpr:
		return ParseExpr(expr.Expr)

	case *sqlparser.MatchExpr:
		// TODO: need to add handling for selectEpr also
		return ParseExpr(expr.Expr)

	case sqlparser.ValTuple:
		// ValTuple represents a tuple of values.
		return ParseExprs(expr...)

	case *sqlparser.FuncExpr: // NOT_NEEDED
	case *sqlparser.GroupConcatExpr: // NOT_NEEDED
	case sqlparser.ListArg: // NOT_NEEDED
		// ListArg represents a list argument.
	case *sqlparser.SQLVal: // NOT_NEEDED
		// SQLVal represents a single value.
	case *sqlparser.NullVal: // NOT_NEEDED
		// NullVal represents a NULL value.
	case sqlparser.BoolVal: // NOT_NEEDED
		// BoolVal represents a boolean value.
	case *sqlparser.ColName: // NOT_NEEDED
		// ColName represents a column name.
	case *sqlparser.ValuesFuncExpr: // NOT_NEEDED
		// just a column name can not use this
	case *sqlparser.Default: // NOT_NEEDED
		// just a column name can not use this
	}

	return nil, nil
}

func getColumnName(expr sqlparser.Expr) string {
	if expr == nil {
		return ""
	}

	switch expr := expr.(type) {
	case *sqlparser.ColName:
		return expr.Name.String()
	}
	return ""
}

func getVal(expr sqlparser.Expr) []byte {
	if expr == nil {
		return nil
	}

	switch expr := expr.(type) {
	case *sqlparser.SQLVal:
		return expr.Val
	}
	return nil
}
