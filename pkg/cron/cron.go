package cron

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
)

type Cron struct {
	cron *cron.Cron
}

func New() *Cron {
	c := cron.New(
		cron.WithChain(
			Recover(), // Recover must be first
			SkipIfStillRunning(),
		),
	)
	return &Cron{cron: c}
}

// Start the cron scheduler in its own goroutine, or no-op if already started.
func (c *Cron) Start() { c.cron.Start() }

// Stop stops the cron scheduler if it is running; otherwise it does nothing.
// A context is returned so the caller can wait for running jobs to complete.
func (c *Cron) Stop() context.Context { return c.cron.Stop() }

// AddFunc adds a func to the Cron to be run on the given schedule.
// It will return error if the provided spec is invalid.
// Spec format: https://pkg.go.dev/github.com/robfig/cron#hdr-CRON_Expression_Format
//
// It is a common in cron jobs to return its job number so that it can be stoped
// easily but as we don't need that thing in pg-collector to stop only one single
// job in between the runs, and hence it is omitted.
func (c *Cron) AddFunc(spec string, cmd func()) error {
	_, err := c.cron.AddJob(spec, cron.FuncJob(cmd))
	return err
}

// Recover is the recover for any the cron job panic. It logs the returned
// panic message at highest possible log level: zerolog.NoLevel
func Recover() cron.JobWrapper {
	const size = 64 << 10
	return func(job cron.Job) cron.Job {
		return cron.FuncJob(func() {
			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]
					err, ok := r.(error)
					if !ok {
						err = fmt.Errorf("%v", r)
					}
					log.Error().Err(err).Msg("Cron job panic")
					log.Info().Str("stack_trace", string(buf)).Msg("")
				}
			}()
			job.Run()
		})
	}
}

// SkipIfStillRunning assures that only one instance of a job is running at a time, by skipping the next runs.
// Meaning, if a job is taking more time than the time interval between its two subsequent schedules, it skips
// the next subsequent invocation of the cron job if its previous invocation is still running, assuring us one
// running instance at a time.
// It is exactly opposite of what DelayIfStillRunning is doing.
func SkipIfStillRunning() cron.JobWrapper {
	return func(job cron.Job) cron.Job {
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		return cron.FuncJob(func() {
			select {
			case v := <-ch:
				job.Run()
				ch <- v
			default:
				log.Info().Msg("A job is skipped, due to previous running invocation")
			}
		})
	}
}

// DelayIfStillRunning assures that only one instance of a job is running at a time, by delaying the next runs.
// Meaning, if a job is taking more time than the time interval between its two subsequent schedules, it delays
// the subsequent runs until the previous one is complete, assuring one running instance at a time.
// It is exactly opposite of what SkipIfStillRunning is doing.
func DelayIfStillRunning() cron.JobWrapper {
	return func(job cron.Job) cron.Job {
		var mu sync.Mutex
		return cron.FuncJob(func() {
			mu.Lock()
			defer mu.Unlock()
			job.Run()
		})
	}
}
