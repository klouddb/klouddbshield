package config

import (
	"os"
	"path/filepath"
	"time"
)

// filterLogFilesByBeginModTime drops Glob matches whose mtime is before begin.
func filterLogFilesByBeginModTime(files []string, begin time.Time) (kept []string, skipped int) {
	if begin.IsZero() || len(files) == 0 {
		return files, 0
	}
	kept = make([]string, 0, len(files))
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			// Keep unreadable paths so the runner can surface the error.
			kept = append(kept, path)
			continue
		}
		if info.ModTime().Before(begin) {
			skipped++
			continue
		}
		kept = append(kept, path)
	}
	return kept, skipped
}

// listLogFiles is Glob + optional begin-time mtime filter.
func listLogFiles(pattern string, begin time.Time) (files []string, skippedBeforeBegin int, err error) {
	files, err = filepath.Glob(pattern)
	if err != nil {
		return nil, 0, err
	}
	files, skippedBeforeBegin = filterLogFilesByBeginModTime(files, begin)
	return files, skippedBeforeBegin, nil
}
