package reportstore

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	cons "github.com/klouddb/klouddbshield/pkg/const"
)

func TestPostgresTextKeepsNULRoundTrip(t *testing.T) {
	prev := UsePostgresPlaceholders
	UsePostgresPlaceholders = true
	t.Cleanup(func() { UsePostgresPlaceholders = prev })

	in := "12\x00host all all 0.0.0.0/0 trust"
	stored := postgresText(in)
	if strings.Contains(stored, "\x00") {
		t.Fatalf("stored text still contains NUL: %q", stored)
	}
	if postgresTextFromDB(stored) != in {
		t.Fatalf("round trip = %q", postgresTextFromDB(stored))
	}

	UsePostgresPlaceholders = false
	if postgresText(in) != in {
		t.Fatal("sqlite path must keep the NUL separator")
	}
}

func TestUnusedHBAKeyStoredOnPostgres(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("postgres", "postgres://postgres:postgres@127.0.0.1:5432/kshield?sslmode=disable")
	if err != nil {
		t.Skip(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Skip(err)
	}

	prev := UsePostgresPlaceholders
	UsePostgresPlaceholders = true
	t.Cleanup(func() { UsePostgresPlaceholders = prev })

	const targetID = "postgres:nul-byte-test:5432:hej"
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM logparser_unused_hba WHERE target_id = $1`, targetID)
	})

	line := "host all all 0.0.0.0/0 trust"
	report := map[string]interface{}{
		"Log Parser Summary": []interface{}{
			map[string]interface{}{
				"Command": cons.LogParserCMD_HBAUnusedLines,
				"Value": []interface{}{
					map[string]interface{}{"LineNo": "12", "Line": line},
				},
			},
		},
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := UpdateLogParserStateFromReport(ctx, db, targetID, "localhost", report, at); err != nil {
		t.Fatal(err)
	}

	var storedKey string
	if err := db.QueryRowContext(ctx, `SELECT entity_key FROM logparser_unused_hba WHERE target_id = $1`, targetID).Scan(&storedKey); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedKey, "\x00") {
		t.Fatalf("postgres stored a NUL byte: %q", storedKey)
	}

	rows, err := ListLogParserUnusedHBALines(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	var got *LogParserUnusedHBAState
	for i := range rows {
		if rows[i].TargetID == targetID {
			got = &rows[i]
			break
		}
	}
	if got == nil {
		t.Fatal("stored row not listed")
	}
	if got.EntityKey != "12\x00"+line || got.LineText != line {
		t.Fatalf("logical row = %+v", *got)
	}

	at2 := at.Add(48 * time.Hour)
	if err := UpdateLogParserStateFromReport(ctx, db, targetID, "localhost", report, at2); err != nil {
		t.Fatal(err)
	}
	rows, err = ListLogParserUnusedHBALines(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.TargetID == targetID && !row.UnusedSince.Equal(at) {
			t.Fatalf("unused since reset to %s", row.UnusedSince)
		}
	}
}
