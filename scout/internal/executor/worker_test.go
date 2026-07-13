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

func TestRunReportsStageProgressAndBoundedTargetCount(t *testing.T) {
	job := testJob(2)
	job.Targets = []string{"192.0.2.1", "198.51.100.0/30"}
	var reports []Progress
	worker := NewTestWorker(time.Millisecond)
	res, err := worker.RunWithProgress(context.Background(), job, func(progress Progress) {
		reports = append(reports, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StagesRun != 2 || len(reports) != 4 {
		t.Fatalf("unexpected result/reports: %+v reports=%d", res, len(reports))
	}
	last := reports[len(reports)-1]
	if last.Percent != 99 || last.StagesCompleted != 2 || last.TargetAddresses != 5 {
		t.Errorf("unexpected final non-terminal progress: %+v", last)
	}
	if reports[0].ETASeconds != nil {
		t.Error("ETA must be absent before a stage provides timing evidence")
	}
	if reports[2].ETASeconds == nil {
		t.Error("ETA should be present after one of two stages finishes")
	}
	if got := TargetAddressCount([]string{"2001:db8::/32"}); got != 1_000_000_000 {
		t.Errorf("large ranges must saturate safely, got %d", got)
	}
}
