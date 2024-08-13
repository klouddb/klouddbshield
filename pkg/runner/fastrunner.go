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

	"github.com/jedib0t/go-pretty/text"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/logger"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

type FastRunnerResponse struct {
	FileErrors   map[string]string
	TotalLines   int64
	SuccessLines []int64
	StartTime    time.Time
}

type Parser interface {
	Feed(string) error
}

type ParserFunc func(string) error

// RunFastParser runs the log parser using fast processing.
func RunFastParser(ctx context.Context, runCmd bool, logParserCnf *config.LogParser, fns []ParserFunc, validator ParserFunc) (*FastRunnerResponse, error) {
	// Read log file path from user
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Caller().Msg("runner recovered from panic")
		}
	}()

	printSuggestion(runCmd)

	start := time.Now()
	h := &ProcessHelper{
		fns:          fns,
		validator:    validator,
		SuccessLines: make([]int64, len(fns)),
	}

	fileErrors := utils.NewLockedKeyValue[string]()
	g, groupCTX := errgroup.WithContext(ctx)
	g.SetLimit(10)

	bar := progressbar.NewOptions(len(logParserCnf.LogFiles),
		progressbar.OptionSetDescription("Processing Log Files"),
		progressbar.OptionShowCount(),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetItsString("files"),
		progressbar.OptionShowIts(),
	)

	// this is to refresh progress bar every second if file is taking more then second to process
	// go func() {
	// 	for range time.NewTicker(time.Second).C {
	bar.RenderBlank() //nolint:errcheck
	// 	}
	// }()

	for _, file := range logParserCnf.LogFiles {
		// handle parallel processing of files\
		func(file string) {
			g.Go(func() error {
				defer bar.Add(1) //nolint:errcheck

				err := h.Process(groupCTX, file)
				if err != nil {
					fileErrors.Add(file, err.Error())
					return nil
				}

				// if context context expired, stop processing
				return groupCTX.Err()
			})
		}(file)
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	fmt.Println()
	return &FastRunnerResponse{
		TotalLines:   h.TotalLines,
		SuccessLines: h.SuccessLines,
		StartTime:    start,
		FileErrors:   fileErrors.Map(),
	}, nil

}

type ProcessHelper struct {
	TotalLines   int64
	SuccessLines []int64

	fns       []ParserFunc
	validator ParserFunc
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

	if fileInfo.Size() == 0 {
		// ignore empty files
		return nil
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

	chunkProcessors := NewChunkProcessor(&linesPool, &stringPool, p.fns)

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
	for i, v := range chunkProcessors.successLines {
		atomic.AddInt64(&p.SuccessLines[i], v)
	}

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
		return fmt.Errorf("logline prefix is wrong")
	}

	return nil
}

// ChunkProcessor processes a chunk of log lines.
type ChunkProcessor struct {
	linesPool, stringPool *sync.Pool
	fns                   []ParserFunc

	totalLines   int64
	successLines []int64
}

// NewChunkProcessor creates a new chunk processor.
func NewChunkProcessor(linesPool *sync.Pool, stringPool *sync.Pool, fns []ParserFunc) *ChunkProcessor {
	return &ChunkProcessor{
		linesPool:  linesPool,
		stringPool: stringPool,
		fns:        fns,

		successLines: make([]int64, len(fns)),
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

				atomic.AddInt64(&c.totalLines, 1)
				for i, fn := range c.fns {
					err := fn(logLine)
					if err != nil {
						logger.FileLogger().Err(err).Str("line", logLine).Msg("Failed to parse line")
						continue
					}
					atomic.AddInt64(&c.successLines[i], 1)
				}
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

func printSuggestion(runCommand bool) {
	fmt.Println(text.FgCyan.Sprint(`NOTE: Scanning large files may cause a spike in CPU usage. If you are using this in a production environment, please take this into consideration. Additionally, large files will take some time to process, so consider processing them in parts`))
	fmt.Println(text.FgCyan.Sprint(`> To control the resource usage, you can limit the number of lines to be processed in a single run. You can do this by using the -cpu-limit flag`))

	if runCommand {
		fmt.Println("\t" + text.FgCyan.Sprint("$ ciscollector -r -cpu-limit 1"))
	} else {
		fmt.Println("\t" + text.FgCyan.Sprint("$ ciscollector --logparser -cpu-limit 1"))
	}

}
