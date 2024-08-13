package cron

import (
	"testing"
	"time"
)

// invalid testcase
func TestCron_AddFunc(t *testing.T) {
	c := New()

	// Define a test job function
	testJob := func() {
		t.Log("Executing test job")
	}

	// Add the test job to the cron scheduler
	err := c.AddFunc("* * * * *", testJob)
	if err != nil {
		t.Fatalf("Failed to add test job to cron scheduler: %v", err)
	}
	c.Start()

	// Wait for a few seconds to allow the job to run
	time.Sleep(5 * time.Second)

	// Stop the cron scheduler
	ctx := c.Stop()
	<-ctx.Done()
}
