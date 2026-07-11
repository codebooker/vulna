// Package agent orchestrates the probe's job lifecycle: it keeps the signed
// local policy up to date, polls for signed jobs, verifies and enforces them
// against the policy, runs the (test) worker, and reports status. It depends on
// an Orchestrator interface so the logic is testable without a live server.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

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
	UploadResults(ctx context.Context, jobID string, raw []byte, stage, scanner string) error
}

// Agent processes jobs for a single probe.
type Agent struct {
	client Orchestrator
	store  *storage.Store
	pubkey ed25519.PublicKey
	worker executor.JobRunner
	queue  *queue.Queue

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

// uploadItem uploads one queued result batch.
func (a *Agent) uploadItem(ctx context.Context, it queue.Item) error {
	return a.client.UploadResults(ctx, it.JobID, it.Raw, it.Stage, it.Scanner)
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
	JobID  string
	cancel context.CancelFunc
	done   chan executor.Result
}

// Cancel stops the running worker.
func (r *RunningJob) Cancel() { r.cancel() }

// Done returns a channel that receives the worker result when it finishes.
func (r *RunningJob) Done() <-chan executor.Result { return r.done }

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

	if err := a.client.ReportJobStatus(ctx, job.JobID, api.JobStatusReport{Status: "accepted"}); err != nil {
		return nil, err
	}
	jobCtx, cancel := context.WithCancel(ctx)
	done := make(chan executor.Result, 1)
	_ = a.client.ReportJobStatus(ctx, job.JobID, api.JobStatusReport{Status: "running"})
	go func() {
		res, _ := a.worker.Run(jobCtx, job)
		done <- res
	}()
	return &RunningJob{JobID: job.JobID, cancel: cancel, done: done}, nil
}

// Finalize delivers each stage's scanner output and reports the terminal status.
//
// With a durable queue attached, outputs are enqueued (surviving a crash or an
// offline link) and then drained best-effort; a drain failure is not fatal —
// the job still completes and the backlog uploads on a later heartbeat. Without
// a queue, outputs upload directly and an upload failure fails the job.
func (a *Agent) Finalize(ctx context.Context, running *RunningJob, res executor.Result) error {
	if !res.Cancelled {
		for _, out := range res.Outputs {
			if len(out.Raw) == 0 {
				continue
			}
			if a.queue != nil {
				if err := a.queue.Enqueue(queue.Item{
					JobID: running.JobID, Stage: out.Stage, Scanner: out.Scanner, Raw: out.Raw,
				}); err != nil {
					return a.client.ReportJobStatus(ctx, running.JobID, api.JobStatusReport{
						Status:       "failed",
						ErrorCode:    "queue_full",
						ErrorMessage: err.Error(),
					})
				}
				continue
			}
			if err := a.client.UploadResults(
				ctx, running.JobID, out.Raw, out.Stage, out.Scanner,
			); err != nil {
				return a.client.ReportJobStatus(ctx, running.JobID, api.JobStatusReport{
					Status:       "failed",
					ErrorCode:    "upload_failed",
					ErrorMessage: err.Error(),
				})
			}
		}
		// Best-effort flush; a failure here leaves work durably queued for retry.
		_, _ = a.DrainQueue(ctx)
	}
	status := "completed"
	if res.Cancelled {
		status = "cancelled"
	}
	return a.client.ReportJobStatus(ctx, running.JobID, api.JobStatusReport{
		Status: status,
		Summary: map[string]any{
			"stages_run":   res.StagesRun,
			"stages_total": res.StagesTotal,
		},
	})
}

func extractJobID(raw []byte) string {
	var v struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.JobID
}
