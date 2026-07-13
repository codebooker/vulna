// Package scanners defines the scanner-plugin interface and a workflow runner
// that dispatches a job's workflow stages to the matching scanner adapters.
package scanners

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/policy"
)

// ValidateTarget ensures a target is a plain IP or CIDR and cannot be mistaken
// for a command flag — an argument-injection defense shared by adapters.
func ValidateTarget(target string) error {
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target %q must not start with '-'", target)
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(target); err == nil {
		return nil
	}
	return fmt.Errorf("target %q is not a valid IP or CIDR", target)
}

// Scanner is a plugin that runs one stage of a workflow against a job's targets
// and returns raw output to upload. Implementations must honor context
// cancellation (the kill switch) and never accept free-form arguments.
type Scanner interface {
	// Stage is the workflow stage the scanner implements (e.g. "discovery").
	Stage() string
	// Name is the plugin name matched against the job workflow (e.g. "nmap").
	Name() string
	// Run executes the scan and returns its raw output.
	Run(ctx context.Context, job *policy.Job) ([]byte, error)
}

// Workflow runs a job's workflow by dispatching each stage's plugin to the
// registered scanner. It satisfies executor.JobRunner.
type Workflow struct {
	byPlugin map[string]Scanner
}

// NewWorkflow registers the given scanners by plugin name.
func NewWorkflow(list ...Scanner) *Workflow {
	byPlugin := make(map[string]Scanner, len(list))
	for _, s := range list {
		byPlugin[s.Name()] = s
	}
	return &Workflow{byPlugin: byPlugin}
}

// Run executes each workflow stage whose plugin is registered, collecting each
// stage's output. Unknown/unavailable plugins are skipped; a stage that errors
// is skipped (continue-with-warning). Cancellation stops promptly.
func (w *Workflow) Run(ctx context.Context, job *policy.Job) (executor.Result, error) {
	return w.RunWithProgress(ctx, job, nil)
}

// RunWithProgress executes the workflow and reports stage boundaries. A long
// scanner stage remains at its last verified percentage instead of fabricating
// work; the current scanner and elapsed time still identify what is running.
func (w *Workflow) RunWithProgress(
	ctx context.Context, job *policy.Job, report executor.ProgressCallback,
) (executor.Result, error) {
	res := executor.Result{JobID: job.JobID, StagesTotal: len(job.Workflow)}
	started := time.Now()
	for _, stage := range job.Workflow {
		stageName, _ := stage["stage"].(string)
		plugin, _ := stage["plugin"].(string)
		reportWorkflowProgress(report, job, res, started, stageName, plugin)
		scanner, ok := w.byPlugin[plugin]
		if !ok {
			// No scanner installed for this stage. Recorded (not silently
			// swallowed) so a job that ran nothing is reported failed, not
			// "completed".
			res.StagesSkipped++
			message := fmt.Sprintf("no scanner installed for plugin %q", plugin)
			res.Errors = append(res.Errors, message)
			res.Failures = append(res.Failures, executor.StageFailure{
				Code: "scanner_unavailable", Stage: stageName, Plugin: plugin, Message: message,
			})
			reportWorkflowProgress(report, job, res, started, stageName, plugin)
			continue
		}
		if ctx.Err() != nil {
			res.Cancelled = true
			return res, ctx.Err()
		}
		raw, err := scanner.Run(ctx, job)
		if ctx.Err() != nil {
			res.Cancelled = true
			return res, ctx.Err()
		}
		if err != nil {
			// The scanner ran but failed — a real error, surfaced (not a silent
			// success). Other stages still run (continue), but the job is failed.
			res.StagesFailed++
			message := fmt.Sprintf("%s failed: %v", scanner.Name(), err)
			res.Errors = append(res.Errors, message)
			res.Failures = append(res.Failures, executor.StageFailure{
				Code: "scanner_error", Stage: stageName, Plugin: scanner.Name(), Message: message,
			})
			reportWorkflowProgress(report, job, res, started, stageName, plugin)
			continue
		}
		res.Outputs = append(res.Outputs, executor.StageOutput{
			Stage: scanner.Stage(), Scanner: scanner.Name(), Raw: raw,
		})
		res.StagesRun++
		reportWorkflowProgress(report, job, res, started, stageName, plugin)
	}
	return res, nil
}

func reportWorkflowProgress(
	report executor.ProgressCallback,
	job *policy.Job,
	res executor.Result,
	started time.Time,
	stage string,
	plugin string,
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
	elapsedDuration := time.Since(started)
	var eta *int
	if completed > 0 && completed < res.StagesTotal {
		remaining := res.StagesTotal - completed
		estimate := int(elapsedDuration.Seconds() * float64(remaining) / float64(completed))
		eta = &estimate
	}
	report(executor.Progress{
		Percent: percent, CurrentStage: stage, CurrentPlugin: plugin,
		StagesTotal: res.StagesTotal, StagesCompleted: completed,
		StagesRun: res.StagesRun, StagesFailed: res.StagesFailed,
		StagesSkipped: res.StagesSkipped, TargetGroups: len(job.Targets),
		TargetAddresses: executor.TargetAddressCount(job.Targets),
		ElapsedSeconds:  int(elapsedDuration.Seconds()), ETASeconds: eta,
	})
}
