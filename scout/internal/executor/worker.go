// Package executor runs assessment jobs. It provides a cancellable test worker
// (simulation) and, via scanner adapters, real multi-stage scans. Runners
// satisfy the JobRunner interface and honor context cancellation (kill switch).
package executor

import (
	"context"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

// StageOutput is raw output produced by one workflow stage, to be uploaded.
type StageOutput struct {
	Stage   string
	Scanner string
	Raw     []byte
}

// Result summarizes a job run.
type Result struct {
	JobID       string
	StagesRun   int
	StagesTotal int
	Cancelled   bool
	// Outputs holds the raw output of each completed stage (empty for the
	// simulation worker, which contacts nothing).
	Outputs []StageOutput
}

// JobRunner executes a verified job and returns its result. Implementations
// must stop promptly when the context is cancelled.
type JobRunner interface {
	Run(ctx context.Context, job *policy.Job) (Result, error)
}

// TestWorker simulates executing a job by stepping through its workflow stages,
// pausing StepDelay between each. It never touches the network. Cancellation via
// the context stops it promptly — this exercises the kill switch in tests.
type TestWorker struct {
	StepDelay time.Duration
}

// NewTestWorker returns a TestWorker with the given per-stage delay.
func NewTestWorker(step time.Duration) *TestWorker {
	return &TestWorker{StepDelay: step}
}

// Run steps through the job's workflow stages, honoring context cancellation.
func (w *TestWorker) Run(ctx context.Context, job *policy.Job) (Result, error) {
	res := Result{JobID: job.JobID, StagesTotal: len(job.Workflow)}
	for range job.Workflow {
		select {
		case <-ctx.Done():
			res.Cancelled = true
			return res, ctx.Err()
		case <-time.After(w.StepDelay):
			res.StagesRun++
		}
	}
	return res, nil
}
