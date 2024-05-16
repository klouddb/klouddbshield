package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/logger"
	"github.com/rs/zerolog/log"
)

type ParserFunc func(string) error

// RunFastParser runs the log parser using fast processing.
func RunFastParser(ctx context.Context, cnf *config.Config, fn, validator ParserFunc) {
	// Read log file path from user
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Caller().Msg("runner recovered from panic")
		}
	}()

	fmt.Printf("Currently parsing the file, please wait...\r")

	start := time.Now()
	h := &ProcessHelper{
		fn:        fn,
		validator: validator,
	}
	var wg sync.WaitGroup

	fileParsingWait := make(chan struct{}, 10)
	for _, file := range cnf.LogParser.LogFiles {
		// handle parallel processing of files
		wg.Add(1)
		fileParsingWait <- struct{}{}
		go func(file string) {
			defer wg.Done()
			defer func() { <-fileParsingWait }()

			err := h.Process(ctx, file)
			if err != nil {
				log.Error().Str("file", file).Err(err).Msg("Failed to process log file")
				return
			}

			// if context context expired, stop processing
			if ctx.Err() != nil {
				return
			}

		}(file)
	}

	wg.Wait()

	if h.TotalLines == 0 {
		fmt.Printf("No log lines found in the log file(s).. Please see error log %s  for additional information\n", logger.GetLogFileName())
		return
	}

	perc := float64(h.SuccessLines) * 100 / float64(h.TotalLines)
	switch perc {
	case 100:
		// added extra space to overrider the previous line proprely
		fmt.Println("Successfully parsed all files                                                                 ")
	case 0:
		fmt.Printf("Was not able to parse logfile(s).. Please see error log %s  for additional information\n", logger.GetLogFileName())
	default:
		fmt.Printf("Was able to partially (%d/%d=%f) parse the logfile(s).. Please see error log %s  for additional information\n", h.SuccessLines, h.TotalLines, perc, logger.GetLogFileName())
	}

	fmt.Printf("Parsed %d files which took: %s\n", len(cnf.LogParser.LogFiles), time.Since(start))
}

type ProcessHelper struct {
	TotalLines, SuccessLines int64

	fn, validator ParserFunc
}

// Process processes the log file in chunks.
func (p *ProcessHelper) Process(ctx context.Context, filename string) error {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Str("file", filename).Caller().Msg("Process recovered from panic")
		}
	}()

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// check if file size is greater than 50GB we will not process that
	fileInfo, err := f.Stat()
	if err != nil {
		return err
	}
	if fileInfo.Size() > 50*1024*1024*1024 {
		return fmt.Errorf("size of this file is %dGB, currently we are not supporting file size greater than 50GB", fileInfo.Size()/(1024*1024*1024))
	}

	linesPool := sync.Pool{New: func() interface{} {
		lines := make([]byte, 250*1024)
		return &lines
	}}

	stringPool := sync.Pool{New: func() interface{} {
		lines := ""
		return &lines
	}}

	err = p.validateFile(ctx, f)
	if err != nil {
		return err
	}

	r := bufio.NewReader(f)

	var wg sync.WaitGroup

	chunkProcessors := NewChunkProcessor(&linesPool, &stringPool, p.fn)

	previousLine := []byte{}
	for {
		// if context context expired, stop processing
		if ctx.Err() != nil {
			return nil
		}

		buf := *(linesPool.Get().(*[]byte))
		buf = append(buf, previousLine...)
		previousLine = nil

		n, err := r.Read(buf[len(previousLine):])
		buf = buf[:n+len(previousLine)]

		if len(buf) == 0 {
			break
		}
		if err != nil {
			return err
		}

		nextUntillNewline, err := r.ReadBytes('\n')
		if err != io.EOF {
			buf = append(buf, nextUntillNewline...)
		}

		// if next line contains tab, then read next line and append to current line
		for {
			nextToNextUntillNewline, err := r.ReadBytes('\n')
			if err != io.EOF && len(nextToNextUntillNewline) > 0 && nextToNextUntillNewline[0] == '\t' {
				buf = append(buf, nextToNextUntillNewline...)
				continue
			}
			previousLine = nextUntillNewline
			break
		}

		wg.Add(1)
		workerController <- struct{}{}
		go func() {
			defer wg.Done()
			chunkProcessors.Parse(ctx, buf)
		}()
	}

	wg.Wait()

	atomic.AddInt64(&p.TotalLines, chunkProcessors.totalLines)
	atomic.AddInt64(&p.SuccessLines, chunkProcessors.successLines)

	return nil
}

func (p *ProcessHelper) validateFile(ctx context.Context, f *os.File) error {

	r := bufio.NewReader(f)
	defer func() {
		_, err := f.Seek(0, io.SeekStart)
		if err != nil {
			log.Error().Err(err).Msg("Failed to seek file to start")
		}
	}()

	errorCount := 0
	totalLine := 0
	for i := 0; i < 100; i++ {
		// if context context expired, stop processing
		if ctx.Err() != nil {
			return nil
		}

		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		line = strings.Trim(line, "\n")

		totalLine++
		err = p.validator(line)
		if err != nil {
			errorCount++
		}
	}

	if totalLine == 0 {
		return fmt.Errorf("no log lines found in the log file")
	}

	if totalLine*70/100 < errorCount {
		return fmt.Errorf("more than 70%% of the lines in the log file are not parsable. Please check the log file format Total Line %d and Error count %d", totalLine, errorCount)
	}

	return nil
}

// ChunkProcessor processes a chunk of log lines.
type ChunkProcessor struct {
	linesPool, stringPool *sync.Pool
	fn                    ParserFunc

	totalLines, successLines int64
}

// NewChunkProcessor creates a new chunk processor.
func NewChunkProcessor(linesPool *sync.Pool, stringPool *sync.Pool, fn ParserFunc) *ChunkProcessor {
	return &ChunkProcessor{
		linesPool:  linesPool,
		stringPool: stringPool,
		fn:         fn,
	}
}

// control the worker routine
var workerController = make(chan struct{}, 2*runtime.NumCPU())

// Parse processes a chunk of log lines.
func (c *ChunkProcessor) Parse(ctx context.Context, chunk []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Caller().Msg("ChunkProcessor recovered from panic")
		}
		<-workerController
	}()

	logs := c.stringPool.Get().(*string)
	*logs = string(chunk)

	c.linesPool.Put(&chunk)

	logLines := mergeContinueLines(strings.Split(*logs, "\n"))

	c.stringPool.Put(logs)

	chunkSize := 30

	var wg sync.WaitGroup

	for i := 0; i < len(logLines); i += chunkSize {
		// if context context expired, stop processing
		if ctx.Err() != nil {
			return
		}

		endIndex := i + chunkSize
		if endIndex > len(logLines) {
			endIndex = len(logLines)
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Caller().Msg("Recovered from panic")
				}
			}()

			for j := start; j < end; j++ {
				// if context context expired, stop processing
				if ctx.Err() != nil {
					return
				}

				logLine := logLines[j]
				if len(logLine) == 0 {
					continue
				}

				// Considering if any line starts with \t then it will be continuation of previous line
				if strings.HasPrefix(logLine, "\t") {
					logger.FileLogger().Warn().Str("line", logLine).Msg("Line starts with tab, skipping")
					continue
				}

				err := c.fn(logLine)
				atomic.AddInt64(&c.totalLines, 1)
				if err != nil {
					logger.FileLogger().Err(err).Str("line", logLine).Msg("Failed to parse line")
					continue
				}
				atomic.AddInt64(&c.successLines, 1)
			}
		}(i, endIndex)
	}

	wg.Wait()
	logLines = nil
}

func mergeContinueLines(lines []string) []string {
	mergedLines := []string{}
	for _, line := range lines {
		if len(mergedLines) == 0 {
			mergedLines = append(mergedLines, line)
			continue
		}

		if len(line) > 0 && line[0] == '\t' {
			mergedLines[len(mergedLines)-1] += line
		} else {
			mergedLines = append(mergedLines, line)
		}
	}

	return mergedLines
}
