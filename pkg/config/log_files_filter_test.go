package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	cons "github.com/klouddb/klouddbshield/pkg/const"
)

func TestFilterLogFilesByBeginModTime(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.log")
	newPath := filepath.Join(dir, "new.log")
	missingPath := filepath.Join(dir, "missing.log")

	if err := os.WriteFile(oldPath, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	newTime := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatal(err)
	}

	begin := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		files       []string
		begin       time.Time
		wantKept    []string
		wantSkipped int
	}{
		{
			name:        "no begin keeps all",
			files:       []string{oldPath, newPath},
			begin:       time.Time{},
			wantKept:    []string{oldPath, newPath},
			wantSkipped: 0,
		},
		{
			name:        "filters files older than begin",
			files:       []string{oldPath, newPath},
			begin:       begin,
			wantKept:    []string{newPath},
			wantSkipped: 1,
		},
		{
			name:        "keeps missing path for later error",
			files:       []string{missingPath, newPath},
			begin:       begin,
			wantKept:    []string{missingPath, newPath},
			wantSkipped: 0,
		},
		{
			name:        "all older than begin",
			files:       []string{oldPath},
			begin:       begin,
			wantKept:    []string{},
			wantSkipped: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, skipped := filterLogFilesByBeginModTime(tt.files, tt.begin)
			if skipped != tt.wantSkipped {
				t.Fatalf("skipped=%d want %d", skipped, tt.wantSkipped)
			}
			if len(kept) != len(tt.wantKept) {
				t.Fatalf("kept=%v want %v", kept, tt.wantKept)
			}
			for i := range kept {
				if kept[i] != tt.wantKept[i] {
					t.Fatalf("kept[%d]=%q want %q", i, kept[i], tt.wantKept[i])
				}
			}
		})
	}
}

func TestNewLogParserFiltersByBeginModTime(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "postgresql-2020.log")
	newPath := filepath.Join(dir, "postgresql-2026.log")
	if err := os.WriteFile(oldPath, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	newTime := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatal(err)
	}

	pattern := filepath.Join(dir, "postgresql-*.log")
	tests := []struct {
		name      string
		begin     string
		wantFiles int
		wantErr   bool
	}{
		{
			name:      "without begin keeps both",
			begin:     "",
			wantFiles: 2,
		},
		{
			name:      "with begin keeps only newer",
			begin:     "2025-01-01 00:00:00",
			wantFiles: 1,
		},
		{
			name:    "begin after all files errors",
			begin:   "2027-01-01 00:00:00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lp, err := NewLogParser(cons.LogParserCMD_UniqueIPs, tt.begin, "", "%t ", pattern, "")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(lp.LogFiles) != tt.wantFiles {
				t.Fatalf("LogFiles=%v want %d files", lp.LogFiles, tt.wantFiles)
			}
			if tt.wantFiles == 1 && lp.LogFiles[0] != newPath {
				t.Fatalf("kept %q want %q", lp.LogFiles[0], newPath)
			}
		})
	}
}
