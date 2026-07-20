// Package agent orchestrates the probe's job lifecycle: it keeps the signed
// local policy up to date, polls for signed jobs, verifies and enforces them
// against the policy, runs the (test) worker, and reports status. It depends on
// an Orchestrator interface so the logic is testable without a live server.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/codebooker/vulna/scout/internal/api"
	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/queue"
	"github.com/codebooker/vulna/scout/internal/storage"
)

// Orchestrator is the subset of the API client the agent needs.
type Orchestrator interface {
	FetchPolicy(ctx context.Context) ([]byte, error)
	PollJob(ctx context.Context) ([]byte, bool, error)
	ReportJobStatus(ctx context.Context, jobID string, report api.JobStatusReport) error
	UploadResults(
		ctx context.Context, jobID string, raw []byte, stage, scanner string, complete ...bool,
	) error
}

// Agent processes jobs for a single probe.
type Agent struct {
	client               Orchestrator
	store                *storage.Store
	pubkey               ed25519.PublicKey
	worker               executor.JobRunner
	queue                *queue.Queue
	credentialPrivateKey []byte

	policy     *policy.Policy
	policyHash string
}

// New builds an Agent.
func New(
	client Orchestrator, store *storage.Store, pubkey ed25519.PublicKey, worker executor.JobRunner,
) *Agent {
	return &Agent{client: client, store: store, pubkey: pubkey, worker: worker}
}

// SetQueue attaches a durable result queue. When set, finished results are
// enqueued and drained (uploaded) best-effort, so work survives an intermittent
// link and resumes without duplicating observations. When nil, results upload
// directly.
func (a *Agent) SetQueue(q *queue.Queue) { a.queue = q }

// SetCredentialPrivateKey supplies the enrollment X25519 key. It is kept only
// in process memory while the Scout runs.
func (a *Agent) SetCredentialPrivateKey(key []byte) {
	a.credentialPrivateKey = append([]byte(nil), key...)
}

// uploadItem uploads one queued result batch.
func (a *Agent) uploadItem(ctx context.Context, it queue.Item) error {
	return a.client.UploadResults(ctx, it.JobID, it.Raw, it.Stage, it.Scanner, it.Complete)
}

// DrainQueue flushes any durably-queued results, returning how many uploaded.
// Called opportunistically from the run loop each heartbeat.
func (a *Agent) DrainQueue(ctx context.Context) (int, error) {
	if a.queue == nil {
		return 0, nil
	}
	return a.queue.Drain(ctx, a.uploadItem)
}

// QueueBacklog reports the pending item count and payload bytes for the heartbeat.
func (a *Agent) QueueBacklog() (count int, bytes int64) {
	if a.queue == nil {
		return 0, 0
	}
	count, bytes, _ = a.queue.Backlog()
	return count, bytes
}

// RunningJob is a job currently executing in the test worker.
type RunningJob struct {
	JobID          string
	cancel         context.CancelCauseFunc
	done           chan executor.Result
	terminalReport *api.JobStatusReport
}

// Cancel stops the running worker.
func (r *RunningJob) Cancel() { r.cancel(errCancellationRequested) }

// Done returns a channel that receives the worker result when it finishes.
func (r *RunningJob) Done() <-chan executor.Result { return r.done }

var (
	errCancellationRequested = errors.New("scan cancellation requested")
	errMaxDurationExceeded   = errors.New("scan maximum duration exceeded")
	errAuthorizationExpired  = errors.New("scan authorization expired")
)

const (
	maxTerminalErrorCodeRunes    = 64
	maxTerminalErrorMessageRunes = 2048
	maxFailureCodeRunes          = 64
	maxFailureStageRunes         = 128
	maxFailurePluginRunes        = 128
	maxFailureMessageRunes       = 2048
	maxTerminalFailureDetails    = 50
)

// SyncPolicy fetches, verifies, caches, and persists the signed local policy.
// A policy that fails signature verification is rejected and not applied.
func (a *Agent) SyncPolicy(ctx context.Context) error {
	raw, err := a.client.FetchPolicy(ctx)
	if err != nil {
		return err
	}
	p, err := policy.Parse(raw, a.pubkey)
	if err != nil {
		return err
	}
	hash, err := policy.DocumentHash(raw)
	if err != nil {
		return err
	}
	a.policy = p
	a.policyHash = hash
	return a.store.SavePolicy(raw)
}

// LoadCachedPolicy loads a previously-persisted local policy from disk into
// memory. Called at startup so a Scout that has already synced keeps enforcing
// its policy — and can keep running jobs — across restarts and while the
// orchestrator is unreachable. Returns false (with no error) when no policy has
// ever been cached, in which case the Scout stays fail-closed until it syncs.
func (a *Agent) LoadCachedPolicy() (bool, error) {
	raw, err := a.store.LoadPolicy()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if len(raw) == 0 {
		return false, nil
	}
	p, err := policy.Parse(raw, a.pubkey)
	if err != nil {
		return false, err
	}
	hash, err := policy.DocumentHash(raw)
	if err != nil {
		return false, err
	}
	a.policy = p
	a.policyHash = hash
	return true, nil
}

// Policy returns the currently cached local policy (nil until synced).
func (a *Agent) Policy() *policy.Policy { return a.policy }

// PolicyHash returns the hash of the cached policy (empty until synced). The run
// loop reports it in heartbeats so the orchestrator can detect a stale policy.
func (a *Agent) PolicyHash() string { return a.policyHash }

// PollAndStart polls for one job. When a valid job is offered it reports
// accepted+running, starts the worker, and returns a RunningJob. An invalid or
// out-of-scope job is rejected (reported as rejected_by_probe) and nil is
// returned. nil is also returned when no job is available.
func (a *Agent) PollAndStart(ctx context.Context) (*RunningJob, error) {
	raw, ok, err := a.client.PollJob(ctx)
	if err != nil || !ok {
		return nil, err
	}

	job, verr := policy.VerifyJob(raw, a.pubkey, a.policy, time.Now().UTC())
	if verr != nil {
		_ = a.client.ReportJobStatus(ctx, extractJobID(raw), api.JobStatusReport{
			Status:       "rejected_by_probe",
			ErrorCode:    "verification_failed",
			ErrorMessage: verr.Error(),
		})
		return nil, nil
	}
	if err := policy.DecryptCredentialEnvelope(job, a.credentialPrivateKey); err != nil {
		_ = a.client.ReportJobStatus(ctx, job.JobID, api.JobStatusReport{
			Status:       "rejected_by_probe",
			ErrorCode:    "credential_envelope_failed",
			ErrorMessage: err.Error(),
		})
		return nil, nil
	}

	if err := a.client.ReportJobStatus(ctx, job.JobID, api.JobStatusReport{Status: "accepted"}); err != nil {
		return nil, err
	}
	deadline, deadlineCause := jobDeadlineCause(job, time.Now().UTC())
	deadlineCtx, stopDeadline := context.WithDeadlineCause(ctx, deadline, deadlineCause)
	jobCtx, cancel := context.WithCancelCause(deadlineCtx)
	done := make(chan executor.Result, 1)
	_ = a.client.ReportJobStatus(ctx, job.JobID, api.JobStatusReport{Status: "running"})
	go func() {
		defer stopDeadline()
		defer job.ClearCredentials()
		res, _ := a.runWithProgress(jobCtx, job)
		if res.Cancelled {
			switch cause := context.Cause(jobCtx); {
			case errors.Is(cause, errMaxDurationExceeded):
				res.CancelReason = executor.CancelReasonMaxDurationExceeded
			case errors.Is(cause, errAuthorizationExpired):
				res.CancelReason = executor.CancelReasonAuthorizationExpiry
			case errors.Is(cause, errCancellationRequested):
				res.CancelReason = executor.CancelReasonRequested
			default:
				res.CancelReason = executor.CancelReasonAgentStopped
			}
		}
		done <- res
	}()
	return &RunningJob{JobID: job.JobID, cancel: cancel, done: done}, nil
}

// jobDeadline is the hard authorization boundary for a running job. The signed
// expiry always wins, while max_duration_seconds also caps the complete workflow
// from the moment execution begins (rather than resetting for every stage/chunk).
func jobDeadline(job *policy.Job, started time.Time) time.Time {
	deadline, _ := jobDeadlineCause(job, started)
	return deadline
}

func jobDeadlineCause(job *policy.Job, started time.Time) (time.Time, error) {
	expiresAt, err := time.Parse(time.RFC3339, job.ExpiresAt)
	if err != nil {
		return started, errAuthorizationExpired
	}
	deadline := expiresAt
	cause := error(errAuthorizationExpired)
	if seconds := job.Limits.MaxDurationSeconds; seconds > 0 {
		limit := started.Add(time.Duration(seconds) * time.Second)
		if limit.Before(deadline) {
			deadline = limit
			cause = errMaxDurationExceeded
		}
	}
	return deadline, cause
}

func (a *Agent) runWithProgress(ctx context.Context, job *policy.Job) (executor.Result, error) {
	reportProgress := func(progress executor.Progress) {
		_ = a.client.ReportJobStatus(ctx, job.JobID, api.JobStatusReport{
			Status: "running",
			Progress: &api.JobProgressReport{
				Percent: progress.Percent, CurrentStage: progress.CurrentStage,
				CurrentPlugin: progress.CurrentPlugin, StagesTotal: progress.StagesTotal,
				StagesCompleted: progress.StagesCompleted, StagesRun: progress.StagesRun,
				StagesFailed: progress.StagesFailed, StagesSkipped: progress.StagesSkipped,
				WorkUnitsTotal: progress.WorkUnitsTotal, WorkUnitsDone: progress.WorkUnitsDone,
				TargetGroups: progress.TargetGroups, TargetAddresses: progress.TargetAddresses,
				ElapsedSeconds: progress.ElapsedSeconds, ETASeconds: progress.ETASeconds,
			},
		})
	}
	// Stream per-chunk results through the durable queue when one is attached: the
	// run loop drains the queue every second while the job runs, so assets and
	// findings appear live instead of only at the end. Content-derived idempotency
	// keys keep each chunk a distinct, de-duplicated upload.
	if streamer, ok := a.worker.(executor.StreamingJobRunner); ok && a.queue != nil {
		return streamer.RunStreaming(ctx, job, reportProgress, func(out executor.StageOutput) error {
			return a.queue.Enqueue(queue.Item{
				JobID: job.JobID, Stage: out.Stage, Scanner: out.Scanner, Raw: out.Raw,
				Complete: out.Complete,
			})
		})
	}
	if progressRunner, ok := a.worker.(executor.ProgressJobRunner); ok {
		return progressRunner.RunWithProgress(ctx, job, reportProgress)
	}
	return a.worker.Run(ctx, job)
}

// Finalize delivers each stage's scanner output and reports the terminal status.
//
// With a durable queue attached, outputs are enqueued (surviving a crash or an
// offline link) and then drained best-effort; a drain failure is not fatal —
// the job still completes and the backlog uploads on a later heartbeat. Without
// a queue, outputs upload directly and an upload failure fails the job.
func (a *Agent) Finalize(ctx context.Context, running *RunningJob, res executor.Result) error {
	// A completed worker remains attached to the RunningJob until the orchestrator
	// acknowledges its terminal state. On retries, send the exact same bounded
	// report without uploading or enqueueing scanner output a second time.
	if running.terminalReport != nil {
		return a.client.ReportJobStatus(ctx, running.JobID, *running.terminalReport)
	}

	if !res.Cancelled {
		for _, out := range res.Outputs {
			if len(out.Raw) == 0 && !out.Complete {
				continue
			}
			if a.queue != nil {
				if err := a.queue.Enqueue(queue.Item{
					JobID: running.JobID, Stage: out.Stage, Scanner: out.Scanner, Raw: out.Raw,
					Complete: out.Complete,
				}); err != nil {
					return a.reportTerminal(ctx, running, api.JobStatusReport{
						Status:       "failed",
						ErrorCode:    "queue_full",
						ErrorMessage: err.Error(),
					})
				}
				continue
			}
			if err := a.client.UploadResults(
				ctx, running.JobID, out.Raw, out.Stage, out.Scanner, out.Complete,
			); err != nil {
				return a.reportTerminal(ctx, running, api.JobStatusReport{
					Status:       "failed",
					ErrorCode:    "upload_failed",
					ErrorMessage: err.Error(),
				})
			}
		}
		// Best-effort flush; a failure here leaves work durably queued for retry.
		_, _ = a.DrainQueue(ctx)
	}
	// A scan that had a scanner error, or ran no stages at all (all scanners
	// missing), is a failure — not a silent "completed". Successful stages'
	// output is still uploaded above.
	status := "completed"
	errCode, errMsg := "", ""
	failureDetails := make([]api.JobFailureDetail, 0, len(res.Failures)+1)
	for _, failure := range res.Failures {
		failureDetails = append(failureDetails, api.JobFailureDetail{
			Code: failure.Code, Stage: failure.Stage,
			Plugin: failure.Plugin, Message: failure.Message,
		})
	}
	switch {
	case res.Cancelled:
		status = "cancelled"
		switch res.CancelReason {
		case executor.CancelReasonMaxDurationExceeded:
			errCode = "max_duration_exceeded"
			errMsg = "Scan stopped after reaching its signed maximum duration"
		case executor.CancelReasonAuthorizationExpiry:
			errCode = "authorization_expired"
			errMsg = "Scan stopped because its signed authorization window expired"
		case executor.CancelReasonRequested:
			errCode = "cancellation_requested"
			errMsg = "Scan was cancelled by an operator request"
		default:
			errCode = "agent_stopped"
			errMsg = "Scan stopped because the Scout execution context ended"
		}
		failureDetails = append(failureDetails, api.JobFailureDetail{
			Code: errCode, Message: errMsg,
		})
	case res.StagesFailed > 0:
		status, errCode = "failed", "scanner_error"
		errMsg = fmt.Sprintf("%d stage(s) failed: %s", res.StagesFailed, strings.Join(res.Errors, "; "))
	case res.StagesRun == 0:
		status, errCode = "failed", "no_stages_ran"
		errMsg = "no scanner stages ran"
		if len(res.Errors) > 0 {
			errMsg += ": " + strings.Join(res.Errors, "; ")
		}
		if len(failureDetails) == 0 {
			failureDetails = append(failureDetails, api.JobFailureDetail{
				Code: errCode, Message: errMsg,
			})
		}
	}
	return a.reportTerminal(ctx, running, api.JobStatusReport{
		Status:         status,
		ErrorCode:      errCode,
		ErrorMessage:   errMsg,
		FailureDetails: failureDetails,
		Summary: map[string]any{
			"stages_run":     res.StagesRun,
			"stages_total":   res.StagesTotal,
			"stages_failed":  res.StagesFailed,
			"stages_skipped": res.StagesSkipped,
			"cancel_reason":  res.CancelReason,
		},
	})
}

// reportTerminal bounds the report to the orchestrator schema and retains it
// on the running job before the first send. A transient status-post failure can
// therefore be retried without repeating result delivery or changing details.
func (a *Agent) reportTerminal(
	ctx context.Context, running *RunningJob, report api.JobStatusReport,
) error {
	report = boundTerminalReport(report)
	running.terminalReport = &report
	return a.client.ReportJobStatus(ctx, running.JobID, report)
}

func boundTerminalReport(report api.JobStatusReport) api.JobStatusReport {
	report.ErrorCode = truncateRunes(report.ErrorCode, maxTerminalErrorCodeRunes)
	report.ErrorMessage = truncateRunes(report.ErrorMessage, maxTerminalErrorMessageRunes)

	details := report.FailureDetails
	if len(details) > maxTerminalFailureDetails {
		// Cancellation diagnostics are appended last and explain why the signed
		// execution stopped, so retain that final detail when trimming the list.
		if report.Status == "cancelled" {
			details = append(
				append([]api.JobFailureDetail(nil), details[:maxTerminalFailureDetails-1]...),
				details[len(details)-1],
			)
		} else {
			details = details[:maxTerminalFailureDetails]
		}
	}
	report.FailureDetails = make([]api.JobFailureDetail, len(details))
	for i, detail := range details {
		if detail.Code == "" {
			detail.Code = "scanner_error"
		}
		if detail.Message == "" {
			detail.Message = "Scanner stage failed without diagnostics"
		}
		detail.Code = truncateRunes(detail.Code, maxFailureCodeRunes)
		detail.Stage = truncateRunes(detail.Stage, maxFailureStageRunes)
		detail.Plugin = truncateRunes(detail.Plugin, maxFailurePluginRunes)
		detail.Message = truncateRunes(detail.Message, maxFailureMessageRunes)
		report.FailureDetails[i] = detail
	}
	return report
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

func extractJobID(raw []byte) string {
	var v struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.JobID
}
