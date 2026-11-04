package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/parselog"
)

func TestProcessFileScanStatuses(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(emptyPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missingPath := filepath.Join(dir, "missing.log")

	oldPath := filepath.Join(dir, "old.log")
	if err := os.WriteFile(oldPath, []byte("2026-01-01 00:00:00 UTC LOG: hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	begin := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	h := &ProcessHelper{
		fns:          []ParserFunc{func(parselog.ParsedData) error { return nil }},
		logParserCnf: &config.LogParser{Begin: begin},
		SuccessLines: make([]int64, 1),
	}

	tests := []struct {
		name       string
		path       string
		wantStatus string
		wantScan   bool
	}{
		{name: "empty file", path: emptyPath, wantStatus: FileScanStatusSkippedEmpty, wantScan: false},
		{name: "before begin", path: oldPath, wantStatus: FileScanStatusSkippedBeforeBegin, wantScan: false},
		{name: "open error", path: missingPath, wantStatus: FileScanStatusError, wantScan: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.Process(context.Background(), tt.path)
			if got.Status != tt.wantStatus {
				t.Fatalf("status=%q want %q err=%q", got.Status, tt.wantStatus, got.Error)
			}
			if got.Scanned != tt.wantScan {
				t.Fatalf("scanned=%v want %v", got.Scanned, tt.wantScan)
			}
			if got.FileName != tt.path {
				t.Fatalf("fileName=%q", got.FileName)
			}
		})
	}
}
