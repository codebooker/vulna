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

// RunStreaming executes the workflow per target chunk, emitting each chunk's
// output through sink the moment it is produced so results can be uploaded — and
// assets/findings surfaced — while the scan is still running. Output handed to
// the sink is not repeated in the returned Result; if the sink rejects a batch,
// it is carried in Result.Outputs so the caller still delivers it. Semantics
// otherwise match RunWithProgress: an unavailable plugin is a skipped stage, a
// scanner error fails that stage, and cancellation stops promptly.
func (w *Workflow) RunStreaming(
	ctx context.Context,
	job *policy.Job,
	report executor.ProgressCallback,
	sink executor.OutputSink,
) (executor.Result, error) {
	res := executor.Result{JobID: job.JobID, StagesTotal: len(job.Workflow)}
	started := time.Now()

	// Resolve which stages have a registered scanner once (registration is
	// static). Unavailable plugins are recorded as skipped so a job that ran
	// nothing is reported failed, not silently "completed".
	type runStage struct {
		scanner Scanner
		stage   string
		plugin  string
	}
	runnable := make([]runStage, 0, len(job.Workflow))
	for _, stage := range job.Workflow {
		stageName, _ := stage["stage"].(string)
		plugin, _ := stage["plugin"].(string)
		scanner, ok := w.byPlugin[plugin]
		if !ok {
			res.StagesSkipped++
			message := fmt.Sprintf("no scanner installed for plugin %q", plugin)
			res.Errors = append(res.Errors, message)
			res.Failures = append(res.Failures, executor.StageFailure{
				Code: "scanner_unavailable", Stage: stageName, Plugin: plugin, Message: message,
			})
			continue
		}
		runnable = append(runnable, runStage{scanner: scanner, stage: stageName, plugin: plugin})
	}

	chunks := ChunkTargets(job.Targets, discoveryChunkAddresses)
	totalUnits := len(chunks) * len(runnable)
	completed := 0
	ran := make([]bool, len(runnable))
	failed := make([]bool, len(runnable))

	emit := func(stage, plugin string) {
		reportStreamingProgress(report, job, res, ran, failed, started, stage, plugin, completed, totalUnits)
	}
	emit("", "")

	for _, chunk := range chunks {
		chunkJob := *job
		chunkJob.Targets = chunk
		for si := range runnable {
			st := runnable[si]
			if ctx.Err() != nil {
				res.Cancelled = true
				return res, ctx.Err()
			}
			raw, err := st.scanner.Run(ctx, &chunkJob)
			if ctx.Err() != nil {
				res.Cancelled = true
				return res, ctx.Err()
			}
			completed++
			if err != nil {
				if !failed[si] {
					message := fmt.Sprintf("%s failed: %v", st.scanner.Name(), err)
					res.Errors = append(res.Errors, message)
					res.Failures = append(res.Failures, executor.StageFailure{
						Code: "scanner_error", Stage: st.stage, Plugin: st.scanner.Name(), Message: message,
					})
					failed[si] = true
				}
				emit(st.stage, st.plugin)
				continue
			}
			ran[si] = true
			if len(raw) > 0 {
				out := executor.StageOutput{Stage: st.scanner.Stage(), Scanner: st.scanner.Name(), Raw: raw}
				if sink == nil {
					res.Outputs = append(res.Outputs, out)
				} else if serr := sink(out); serr != nil {
					// The sink (e.g. a full durable queue) rejected the batch; carry
					// it so Finalize still delivers it.
					res.Outputs = append(res.Outputs, out)
				}
			}
			emit(st.stage, st.plugin)
		}
	}
	for si := range runnable {
		switch {
		case failed[si]:
			res.StagesFailed++
		case ran[si]:
			res.StagesRun++
		}
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

// reportStreamingProgress reports percent by completed (chunk × stage) work units
// so the bar advances smoothly across chunks. Stage tallies are computed live
// from the per-stage outcome so the UI reflects what has run so far.
func reportStreamingProgress(
	report executor.ProgressCallback,
	job *policy.Job,
	res executor.Result,
	ran, failed []bool,
	started time.Time,
	stage, plugin string,
	completed, totalUnits int,
) {
	if report == nil {
		return
	}
	liveRun, liveFailed := 0, 0
	for i := range ran {
		switch {
		case failed[i]:
			liveFailed++
		case ran[i]:
			liveRun++
		}
	}
	percent := 0
	if totalUnits > 0 {
		percent = completed * 100 / totalUnits
		if percent >= 100 {
			percent = 99
		}
	}
	elapsed := time.Since(started)
	var eta *int
	if completed > 0 && completed < totalUnits {
		estimate := int(elapsed.Seconds() * float64(totalUnits-completed) / float64(completed))
		eta = &estimate
	}
	report(executor.Progress{
		Percent: percent, CurrentStage: stage, CurrentPlugin: plugin,
		StagesTotal:     res.StagesTotal,
		StagesCompleted: liveRun + liveFailed + res.StagesSkipped,
		StagesRun:       liveRun, StagesFailed: liveFailed, StagesSkipped: res.StagesSkipped,
		TargetGroups:    len(job.Targets),
		TargetAddresses: executor.TargetAddressCount(job.Targets),
		ElapsedSeconds:  int(elapsed.Seconds()), ETASeconds: eta,
	})
}
