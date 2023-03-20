package rds

import (
	"log"

	"golang.org/x/net/context"

	"sync"
	"time"
)

type GoPool struct {
	wg        sync.WaitGroup
	cancelctx context.Context
	canclFunc context.CancelFunc
}

// NewGoPool is a function which takes a context and exits when the context is done.
func NewGoPool(ctx context.Context) *GoPool {
	cancelctx, canclFunc := context.WithCancel(ctx)
	return &GoPool{
		cancelctx: cancelctx,
		canclFunc: canclFunc,
	}
}

func (gp *GoPool) Context() context.Context {
	return gp.cancelctx
}

func (gp *GoPool) WaitGroup() *sync.WaitGroup {
	return &gp.wg
}

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func (gp *GoPool) waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func (gp *GoPool) ShutDown(waitforver bool, timeout time.Duration) {
	gp.canclFunc()
	if waitforver {
		gp.wg.Wait()
	} else {
		gp.waitTimeout(&gp.wg, timeout)
	}

}

// this request a shutdown and doesnt wait for shutdown to happen. typically this can be called inside
// the jobs that are spawned so that they can exit and make other go routines also exit.
func (gp *GoPool) RequestShutDown() {
	gp.canclFunc()
}

func (gp *GoPool) AddJob(method string, fn func(ctx context.Context, args ...interface{}) error, args ...interface{}) {
	gp.wg.Add(1)

	go func() {
		defer func() {
			gp.wg.Done()
		}()
		err := fn(gp.Context(), args...)
		if err != nil {
			log.Println("error in job", err.Error())
		}
	}()
}
