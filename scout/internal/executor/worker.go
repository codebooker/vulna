// Package executor runs assessment jobs. It provides a cancellable test worker
// (simulation) and, via scanner adapters, real multi-stage scans. Runners
// satisfy the JobRunner interface and honor context cancellation (kill switch).
package executor

import (
	"context"
	"net/netip"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

// StageOutput is raw output produced by one workflow stage, to be uploaded.
type StageOutput struct {
	Stage   string
	Scanner string
	Raw     []byte
}

// StageFailure is a structured diagnostic for an unavailable or failed stage.
// The orchestrator sanitizes every field again before durable storage.
type StageFailure struct {
	Code    string
	Stage   string
	Plugin  string
	Message string
}

// Progress is an honest stage-level execution snapshot. Percent advances only
// after a stage finishes; ETA is omitted until completed-stage timing exists.
type Progress struct {
	Percent         int
	CurrentStage    string
	CurrentPlugin   string
	StagesTotal     int
	StagesCompleted int
	StagesRun       int
	StagesFailed    int
	StagesSkipped   int
	TargetGroups    int
	TargetAddresses int
	ElapsedSeconds  int
	ETASeconds      *int
}

// ProgressCallback receives non-terminal progress snapshots.
type ProgressCallback func(Progress)

// Result summarizes a job run.
type Result struct {
	JobID       string
	StagesRun   int
	StagesTotal int
	// StagesFailed is stages whose scanner ran but errored; StagesSkipped is
	// stages with no matching scanner installed. Errors carries the details.
	StagesFailed  int
	StagesSkipped int
	Errors        []string
	Failures      []StageFailure
	Cancelled     bool
	// Outputs holds the raw output of each completed stage (empty for the
	// simulation worker, which contacts nothing).
	Outputs []StageOutput
}

// JobRunner executes a verified job and returns its result. Implementations
// must stop promptly when the context is cancelled.
type JobRunner interface {
	Run(ctx context.Context, job *policy.Job) (Result, error)
}

// ProgressJobRunner is implemented by runners that can report trustworthy
// execution checkpoints without changing the established JobRunner contract.
type ProgressJobRunner interface {
	RunWithProgress(ctx context.Context, job *policy.Job, report ProgressCallback) (Result, error)
}

// OutputSink receives a stage's raw output the moment it is produced, letting a
// runner deliver results incrementally (per target chunk) instead of only at the
// end of the job. A non-nil error means the sink could not accept the output, so
// the runner carries it in the Result for the caller to deliver instead.
type OutputSink func(StageOutput) error

// StreamingJobRunner is implemented by runners that can emit each target chunk's
// output through a sink as the scan progresses, so assets and findings appear
// live. Output delivered to the sink is not repeated in the returned Result.
type StreamingJobRunner interface {
	RunStreaming(
		ctx context.Context, job *policy.Job, report ProgressCallback, sink OutputSink,
	) (Result, error)
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
	return w.RunWithProgress(ctx, job, nil)
}

// RunWithProgress steps through the simulated workflow and reports stage
// boundaries. It is used for local/demo validation and never touches a target.
func (w *TestWorker) RunWithProgress(
	ctx context.Context, job *policy.Job, report ProgressCallback,
) (Result, error) {
	res := Result{JobID: job.JobID, StagesTotal: len(job.Workflow)}
	started := time.Now()
	for _, workflowStage := range job.Workflow {
		stage, _ := workflowStage["stage"].(string)
		plugin, _ := workflowStage["plugin"].(string)
		reportProgress(report, job, res, started, stage, plugin)
		select {
		case <-ctx.Done():
			res.Cancelled = true
			return res, ctx.Err()
		case <-time.After(w.StepDelay):
			res.StagesRun++
			reportProgress(report, job, res, started, stage, plugin)
		}
	}
	return res, nil
}

// TargetAddressCount returns a bounded address estimate for IP/CIDR targets.
func TargetAddressCount(targets []string) int {
	const maximum = 1_000_000_000
	total := 0
	for _, target := range targets {
		count := 1
		if prefix, err := netip.ParsePrefix(target); err == nil {
			hostBits := prefix.Addr().BitLen() - prefix.Bits()
			if hostBits >= 30 {
				return maximum
			}
			count = 1 << hostBits
		}
		if total > maximum-count {
			return maximum
		}
		total += count
	}
	return total
}

func reportProgress(
	report ProgressCallback, job *policy.Job, res Result, started time.Time, stage, plugin string,
) {
	if report == nil {
		return
	}
	completed := res.StagesRun + res.StagesFailed + res.StagesSkipped
	percent := 0
	if res.StagesTotal > 0 {
		percent = completed * 100 / res.StagesTotal
		if percent >= 100 {
			percent = 99
		}
	}
	elapsed := int(time.Since(started).Seconds())
	var eta *int
	if completed > 0 && completed < res.StagesTotal {
		remaining := res.StagesTotal - completed
		estimate := int(time.Since(started).Seconds() * float64(remaining) / float64(completed))
		eta = &estimate
	}
	report(Progress{
		Percent: percent, CurrentStage: stage, CurrentPlugin: plugin,
		StagesTotal: res.StagesTotal, StagesCompleted: completed,
		StagesRun: res.StagesRun, StagesFailed: res.StagesFailed,
		StagesSkipped: res.StagesSkipped, TargetGroups: len(job.Targets),
		TargetAddresses: TargetAddressCount(job.Targets), ElapsedSeconds: elapsed,
		ETASeconds: eta,
	})
}
