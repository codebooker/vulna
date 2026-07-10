// Package executor runs assessment jobs. It provides a cancellable test worker
// (simulation) and, via the Nmap adapter, real discovery scans. Both satisfy
// the JobRunner interface and honor context cancellation (the kill switch).
package executor

import (
	"context"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

// Result summarizes a job run.
type Result struct {
	JobID           string
	StagesRun       int
	StagesTotal     int
	Cancelled       bool
	CompletedStages []string
	// RawOutput is the scanner's raw output to upload (empty for the simulation).
	RawOutput []byte
	Scanner   string
	Stage     string
}

// JobRunner executes a verified job and returns its result. Implementations
// must stop promptly when the context is cancelled.
type JobRunner interface {
	Run(ctx context.Context, job *policy.Job) (Result, error)
}

// TestWorker simulates executing a job by stepping through its workflow stages,
// pausing StepDelay between each. It never touches the network. Cancellation via
// the context stops it promptly — this is what exercises the kill switch until
// real scanners exist.
type TestWorker struct {
	StepDelay time.Duration
}

// NewTestWorker returns a TestWorker with the given per-stage delay.
func NewTestWorker(step time.Duration) *TestWorker {
	return &TestWorker{StepDelay: step}
}

// Run executes the job's workflow stages, honoring context cancellation. It
// returns a Result describing how far it got; Cancelled is true if the context
// was cancelled before all stages completed.
func (w *TestWorker) Run(ctx context.Context, job *policy.Job) (Result, error) {
	stages := job.Workflow
	res := Result{JobID: job.JobID, StagesTotal: len(stages)}
	for _, stage := range stages {
		select {
		case <-ctx.Done():
			res.Cancelled = true
			return res, ctx.Err()
		case <-time.After(w.StepDelay):
			name, _ := stage["stage"].(string)
			res.StagesRun++
			res.CompletedStages = append(res.CompletedStages, name)
		}
	}
	return res, nil
}
