package reportstore

import (
	"context"
	"database/sql"
)

func execContext(ctx context.Context, db *sql.DB, query string, args ...interface{}) (sql.Result, error) {
	return db.ExecContext(ctx, rebindSQL(db, query), args...)
}

func queryContext(ctx context.Context, db *sql.DB, query string, args ...interface{}) (*sql.Rows, error) {
	return db.QueryContext(ctx, rebindSQL(db, query), args...)
}

func queryRowContext(ctx context.Context, db *sql.DB, query string, args ...interface{}) *sql.Row {
	return db.QueryRowContext(ctx, rebindSQL(db, query), args...)
}
