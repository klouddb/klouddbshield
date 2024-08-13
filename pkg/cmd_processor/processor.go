package cmdprocessor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
)

type CmdProcessor struct {
	name string
	args []string

	mt sync.Mutex

	inputChan  chan string
	outputChan chan string
	errChan    chan error

	readerEnded atomic.Bool
	writerEnded atomic.Bool

	tty *os.File

	processTimeout time.Duration

	skipMethod, waitMethod func(string) (bool, error)
}

func NewCmdProcessor(name string, args ...string) *CmdProcessor {
	return &CmdProcessor{
		name: name,
		args: args,

		processTimeout: 5 * time.Second,
	}
}

func (c *CmdProcessor) SetProcessTimeout(timeout time.Duration) *CmdProcessor {
	c.processTimeout = timeout
	return c
}

func (c *CmdProcessor) SetSkipMethod(skipMethod func(string) (bool, error)) *CmdProcessor {
	c.skipMethod = skipMethod
	return c
}

func (c *CmdProcessor) SetWaitMethod(waitMethod func(string) (bool, error)) *CmdProcessor {
	c.waitMethod = waitMethod
	return c
}

func (c *CmdProcessor) Start(ctx context.Context) error {
	c.mt.Lock()
	defer c.mt.Unlock()

	c.errChan = make(chan error)
	c.inputChan = make(chan string)
	c.outputChan = make(chan string)

	cmd := exec.CommandContext(ctx, c.name, c.args...)
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 80})
	if err != nil {
		return fmt.Errorf("error while starting command %v : %v", c.name, err)
	}

	c.tty = tty

	go c.inputFunction()
	go c.outputFunction()

	// err = cmd.Start()
	// if err != nil {
	// 	return fmt.Errorf("error while executing command %v : %v", c.name, err)
	// }

	go func() {
		defer func() {
			close(c.inputChan)
			defer tty.Close()

		}()

		err := cmd.Wait()
		if err != nil {
			c.pushError(fmt.Errorf("Error while waiting for command to finish: %v", err))
		}

	}()

	if c.waitMethod == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Context cancelled")
		case err := <-c.errChan:
			return err
		case <-time.After(2 * time.Minute):
			return fmt.Errorf("Timeout while waiting for method")
		case data := <-c.outputChan:
			wait, err := c.waitMethod(data)
			if err != nil {
				return err
			}

			if !wait {
				return nil
			}

		}
	}
}

func (c *CmdProcessor) pushError(err error) {

	t := time.NewTimer(c.processTimeout)
	select {
	case <-t.C:
		return
	case c.errChan <- err:
	}
}

func (c *CmdProcessor) inputFunction() {
	defer c.writerEnded.Store(true)

	for msg := range c.inputChan {
		if c.readerEnded.Load() {
			return
		}

		_, err := c.tty.Write(append([]byte(msg), '\n'))
		if err != nil {
			c.pushError(fmt.Errorf("Error while writing to PTY: %v", err))
			return
		}
	}
}

func (c *CmdProcessor) outputFunction() {
	defer c.readerEnded.Store(true)

	bufioReader := bufio.NewReader(c.tty)
	for {
		if c.writerEnded.Load() {
			return
		}

		buf, err := bufioReader.ReadBytes('\n')
		if err != nil {
			c.pushError(fmt.Errorf("Error while reading from PTY: %v", err))
			continue
		}

		if !strings.HasPrefix(string(buf), "{") {
			// ignore non-json messages
			continue
		}

		c.outputChan <- string(buf)
	}
}

func (c *CmdProcessor) Process(msg string) (string, error) {
	c.mt.Lock()
	defer c.mt.Unlock()

	if c.writerEnded.Load() {
		return "", fmt.Errorf("Writer has ended")
	}

	if c.readerEnded.Load() {
		return "", fmt.Errorf("Reader has ended")
	}

	t := time.NewTimer(c.processTimeout)
	defer t.Stop()

	select {
	case <-t.C:
		return "", fmt.Errorf("Timeout while while passing message to spacy")
	case err := <-c.errChan:
		return "", fmt.Errorf("Error while passing message to spacy %v", err)
	case c.inputChan <- msg:
	}

	for {
		select {
		case <-t.C:
			return "", fmt.Errorf("Timeout while waiting for response from spacy (%v)", msg)
		case <-c.errChan:
			return "", fmt.Errorf("Error while waiting for response from spacy")
		case out := <-c.outputChan:
			if c.skipMethod == nil {
				return out, nil
			}

			skip, err := c.skipMethod(out)
			if err != nil {
				return "", fmt.Errorf("Error while checking if message should be skipped: %v", err)
			}

			if !skip {
				return out, nil
			}
		}
	}

}
