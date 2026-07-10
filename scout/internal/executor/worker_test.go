package executor

import (
	"context"
	"testing"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func testJob(stages int) *policy.Job {
	wf := make([]map[string]any, stages)
	for i := range wf {
		wf[i] = map[string]any{"stage": "discovery", "plugin": "nmap"}
	}
	return &policy.Job{JobID: "j1", Workflow: wf}
}

func TestRunCompletesAllStages(t *testing.T) {
	w := NewTestWorker(time.Millisecond)
	res, err := w.Run(context.Background(), testJob(3))
	if err != nil {
		t.Fatal(err)
	}
	if res.Cancelled {
		t.Error("expected not cancelled")
	}
	if res.StagesRun != 3 || res.StagesTotal != 3 {
		t.Errorf("stages run=%d total=%d", res.StagesRun, res.StagesTotal)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	// A long per-stage delay so cancellation clearly interrupts execution.
	w := NewTestWorker(10 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() {
		res, _ := w.Run(ctx, testJob(100))
		done <- res
	}()
	// Let it enter the first stage, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case res := <-done:
		if !res.Cancelled {
			t.Error("expected worker to report cancellation")
		}
		if res.StagesRun >= 100 {
			t.Errorf("worker should have stopped early, ran %d stages", res.StagesRun)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop promptly after cancellation")
	}
}
