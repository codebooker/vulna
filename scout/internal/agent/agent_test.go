package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/codebooker/vulna/scout/internal/api"
	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/queue"
	"github.com/codebooker/vulna/scout/internal/storage"
)

// Cross-language vectors: one Python key signed both a policy and a job whose
// target (10.20.0.5/32) is within the policy scope (10.20.0.0/24).
const (
	agentPub    = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	agentPolicy = `{"schema_version": 1, "policy_version": 4, "probe_id": "p1", "site_id": "s1", "approved_cidrs": ["10.20.0.0/24"], "denied_cidrs": [], "allow_public_addresses": false, "allowed_modes": ["vulnerability_assessment"], "allowed_plugins": ["nmap"], "active_web_scans_allowed": false, "credentialed_scans_allowed": false, "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "mirXEAyswKQuI7n8tcKGFYiaZaqn1VpxtUSg3XMKJhG9i0MgqZBxFJj1pNIPVCTxpCWJNiMnqUZEytLIE8mDBw=="}`
	agentJob    = `{"schema_version": 1, "job_id": "job-123", "probe_id": "p1", "site_id": "s1", "mode": "vulnerability_assessment", "profile_version": 1, "policy_version": 4, "not_before": "2020-01-01T00:00:00+00:00", "expires_at": "2030-01-01T00:00:00+00:00", "targets": ["10.20.0.5/32"], "workflow": [{"stage": "discovery", "plugin": "nmap", "config": {}}], "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "A07Uz317F18t8r1Tnk/sjrvkvGQ+pnbJch/RS6phrlKoxKsLHYrW5gmFU2i+CT0R2DFmAXzMvAFW8N04/2P4Dg=="}`
)

var agentAttempt = api.AttemptRef{
	AttemptID: "11111111-1111-1111-1111-111111111111",
	LeaseID:   "22222222-2222-2222-2222-222222222222", FencingToken: 1,
}

type fakeOrch struct {
	mu             sync.Mutex
	policy         []byte
	job            []byte
	jobServed      bool
	reports        []api.JobStatusReport
	uploads        int
	uploaded       []byte
	uploadErr      error // when set, uploads fail (simulates an offline link)
	renewErr       error
	reportFailures int
}

func (f *fakeOrch) FetchPolicy(context.Context) ([]byte, error) { return f.policy, nil }

func (f *fakeOrch) UploadResults(
	_ context.Context, _ string, _ api.AttemptRef, raw []byte, _, _ string, _ ...bool,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploadErr != nil {
		return f.uploadErr
	}
	f.uploads++
	f.uploaded = raw
	return nil
}

func (f *fakeOrch) setUploadErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploadErr = err
}

func (f *fakeOrch) PollJob(context.Context) (api.JobOffer, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jobServed || f.job == nil {
		return api.JobOffer{}, false, nil
	}
	f.jobServed = true
	return api.JobOffer{Envelope: f.job, Attempt: agentAttempt}, true, nil
}

func (f *fakeOrch) ReportJobStatus(
	_ context.Context, _ string, _ api.AttemptRef, r api.JobStatusReport,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
	if f.reportFailures > 0 {
		f.reportFailures--
		return errors.New("temporary status failure")
	}
	return nil
}

func (f *fakeOrch) RenewJobLease(context.Context, string, api.AttemptRef) error {
	return f.renewErr
}

func TestLeaseRenewalFailureStopsBeforeServerLeaseExpires(t *testing.T) {
	f := &fakeOrch{renewErr: errors.New("orchestrator unreachable")}
	a := newAgent(t, f, time.Millisecond)
	jobCtx, cancel := context.WithCancelCause(context.Background())
	running := &RunningJob{
		JobID: "job-1", Attempt: agentAttempt, cancel: cancel,
		lastLeaseRenewal: time.Now().Add(-leaseFailureLimit),
	}
	if err := a.RenewLease(context.Background(), running); err == nil {
		t.Fatal("expected renewal error")
	}
	select {
	case <-jobCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("job continued beyond the safe lease-renewal window")
	}
}

func (f *fakeOrch) statuses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.reports))
	for i, r := range f.reports {
		out[i] = r.Status
	}
	return out
}

func newAgent(t *testing.T, f *fakeOrch, step time.Duration) *Agent {
	t.Helper()
	pub, err := policy.ParsePublicKey(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(f, st, pub, executor.NewTestWorker(step))
}

func TestSyncPolicyCachesAndPersists(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy)}
	a := newAgent(t, f, time.Millisecond)
	if err := a.SyncPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Policy() == nil {
		t.Fatal("policy not cached")
	}
}

func TestSyncPolicyRejectsAltered(t *testing.T) {
	altered := strings.Replace(agentPolicy, "10.20.0.0/24", "10.99.0.0/24", 1)
	f := &fakeOrch{policy: []byte(altered)}
	a := newAgent(t, f, time.Millisecond)
	if err := a.SyncPolicy(context.Background()); err == nil {
		t.Fatal("expected altered policy to be rejected")
	}
}

func TestJobRunsToCompletion(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(agentJob)}
	a := newAgent(t, f, time.Millisecond)
	ctx := context.Background()
	if err := a.SyncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	running, err := a.PollAndStart(ctx)
	if err != nil || running == nil {
		t.Fatalf("expected a running job, err=%v", err)
	}
	res := <-running.Done()
	if res.Cancelled {
		t.Error("job should have completed, not cancelled")
	}
	if err := a.Finalize(ctx, running, res); err != nil {
		t.Fatal(err)
	}
	got := f.statuses()
	for _, want := range []string{"accepted", "running", "completed"} {
		if !contains(got, want) {
			t.Errorf("missing status %q in %v", want, got)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	progressReports := 0
	for _, report := range f.reports {
		if report.Progress != nil {
			progressReports++
			if report.Status != "running" || report.Progress.TargetAddresses != 1 {
				t.Errorf("unexpected progress report: %+v", report)
			}
		}
	}
	if progressReports == 0 {
		t.Error("progress-capable workers must report live stage statistics")
	}
}

func TestJobCancellation(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(agentJob)}
	a := newAgent(t, f, 10*time.Second) // long per-stage delay
	ctx := context.Background()
	if err := a.SyncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	running, err := a.PollAndStart(ctx)
	if err != nil || running == nil {
		t.Fatalf("expected a running job, err=%v", err)
	}
	time.Sleep(20 * time.Millisecond)
	running.Cancel()
	res := <-running.Done()
	if !res.Cancelled {
		t.Fatal("worker should have been cancelled")
	}
	_ = a.Finalize(ctx, running, res)
	if got := f.statuses(); !contains(got, "cancelled") {
		t.Errorf("expected a cancelled report, got %v", got)
	}
	f.mu.Lock()
	last := f.reports[len(f.reports)-1]
	f.mu.Unlock()
	if last.ErrorCode != "cancellation_requested" || len(last.FailureDetails) != 1 {
		t.Fatalf("cancel reason was not reported: %+v", last)
	}
}

func TestFinalizeReportsMaximumDurationCancellation(t *testing.T) {
	f := &fakeOrch{}
	a := &Agent{client: f}
	running := &RunningJob{JobID: "timed-out-job"}
	res := executor.Result{
		JobID: "timed-out-job", StagesTotal: 3, Cancelled: true,
		CancelReason: executor.CancelReasonMaxDurationExceeded,
	}
	if err := a.Finalize(context.Background(), running, res); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.reports[len(f.reports)-1]
	if last.Status != "cancelled" || last.ErrorCode != "max_duration_exceeded" {
		t.Fatalf("deadline cancellation was not explained: %+v", last)
	}
	if len(last.FailureDetails) != 1 || last.FailureDetails[0].Code != "max_duration_exceeded" {
		t.Fatalf("deadline diagnostics missing: %+v", last.FailureDetails)
	}
}

func TestAlteredJobRejected(t *testing.T) {
	altered := strings.Replace(agentJob, "10.20.0.5/32", "10.99.0.5/32", 1)
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(altered)}
	a := newAgent(t, f, time.Millisecond)
	ctx := context.Background()
	if err := a.SyncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	running, err := a.PollAndStart(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if running != nil {
		t.Fatal("an altered job must not start")
	}
	if got := f.statuses(); !contains(got, "rejected_by_probe") {
		t.Errorf("expected rejected_by_probe, got %v", got)
	}
}

type stubRunner struct{ raw []byte }

func (s stubRunner) Run(_ context.Context, job *policy.Job) (executor.Result, error) {
	return executor.Result{
		JobID: job.JobID,
		Outputs: []executor.StageOutput{
			{Stage: "discovery", Scanner: "nmap", Raw: s.raw},
		},
		StagesRun: 1, StagesTotal: 1,
	}, nil
}

func TestFinalizeUploadsResults(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(agentJob)}
	pub, err := policy.ParsePublicKey(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := New(f, st, pub, stubRunner{raw: []byte("<nmaprun/>")})
	ctx := context.Background()
	if err := a.SyncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	running, err := a.PollAndStart(ctx)
	if err != nil || running == nil {
		t.Fatalf("expected a running job, err=%v", err)
	}
	res := <-running.Done()
	if err := a.Finalize(ctx, running, res); err != nil {
		t.Fatal(err)
	}
	if f.uploads != 1 {
		t.Errorf("expected 1 result upload, got %d", f.uploads)
	}
	if string(f.uploaded) != "<nmaprun/>" {
		t.Errorf("unexpected uploaded content: %q", f.uploaded)
	}
	if !contains(f.statuses(), "completed") {
		t.Errorf("expected completed status, got %v", f.statuses())
	}
}

func TestFinalizeQueuesWhenOfflineAndResumes(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(agentJob)}
	f.setUploadErr(errors.New("network down"))

	pub, err := policy.ParsePublicKey(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := New(f, st, pub, stubRunner{raw: []byte("<nmaprun/>")})
	q, err := queue.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	a.SetQueue(q)

	ctx := context.Background()
	if err := a.SyncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	running, err := a.PollAndStart(ctx)
	if err != nil || running == nil {
		t.Fatalf("expected a running job, err=%v", err)
	}
	res := <-running.Done()

	// Offline: Finalize preserves the work and still reports the job completed.
	if err := a.Finalize(ctx, running, res); err != nil {
		t.Fatal(err)
	}
	if !contains(f.statuses(), "completed") {
		t.Errorf("job should complete even when offline, got %v", f.statuses())
	}
	if f.uploads != 0 {
		t.Errorf("nothing should have uploaded while offline, got %d", f.uploads)
	}
	if n, _ := a.QueueBacklog(); n != 1 {
		t.Fatalf("expected 1 item preserved in the queue, got %d", n)
	}

	// Reconnect: the backlog drains exactly once, no duplicate observation.
	f.setUploadErr(nil)
	uploaded, err := a.DrainQueue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if uploaded != 1 || f.uploads != 1 {
		t.Errorf("expected exactly 1 upload on resume, drained=%d uploads=%d", uploaded, f.uploads)
	}
	if n, _ := a.QueueBacklog(); n != 0 {
		t.Errorf("queue should be empty after resume, got %d", n)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestFinalizeReportsFailedOnScannerError(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(agentJob)}
	pub, _ := policy.ParsePublicKey(agentPub)
	st, _ := storage.New(t.TempDir())
	a := New(f, st, pub, stubRunner{raw: []byte("x")})
	ctx := context.Background()
	_ = a.SyncPolicy(ctx)
	running, err := a.PollAndStart(ctx)
	if err != nil || running == nil {
		t.Fatalf("expected a running job: %v", err)
	}
	res := executor.Result{
		JobID: running.JobID, StagesTotal: 1, StagesFailed: 1,
		Errors: []string{"nmap failed"},
		Failures: []executor.StageFailure{{
			Code: "scanner_error", Stage: "discovery", Plugin: "nmap", Message: "nmap failed",
		}},
	}
	_ = a.Finalize(ctx, running, res)
	if !contains(f.statuses(), "failed") {
		t.Errorf("a scanner error must report failed, got %v", f.statuses())
	}
	if contains(f.statuses(), "completed") {
		t.Error("a failed scan must not also report completed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.reports[len(f.reports)-1]
	if len(last.FailureDetails) != 1 || last.FailureDetails[0].Plugin != "nmap" {
		t.Errorf("expected structured terminal failure details, got %+v", last)
	}
}

func TestFinalizeReportsFailedWhenNothingRan(t *testing.T) {
	f := &fakeOrch{policy: []byte(agentPolicy), job: []byte(agentJob)}
	pub, _ := policy.ParsePublicKey(agentPub)
	st, _ := storage.New(t.TempDir())
	a := New(f, st, pub, stubRunner{raw: []byte("x")})
	ctx := context.Background()
	_ = a.SyncPolicy(ctx)
	running, _ := a.PollAndStart(ctx)
	res := executor.Result{JobID: running.JobID, StagesTotal: 1, StagesRun: 0, StagesSkipped: 1}
	_ = a.Finalize(ctx, running, res)
	if !contains(f.statuses(), "failed") {
		t.Errorf("a scan that ran nothing must report failed, got %v", f.statuses())
	}
}

func TestFinalizeRetriesTerminalStatusWithoutUploadingTwice(t *testing.T) {
	f := &fakeOrch{reportFailures: 1}
	a := &Agent{client: f}
	running := &RunningJob{JobID: "retry-terminal-job"}
	res := executor.Result{
		JobID: "retry-terminal-job", StagesRun: 1, StagesTotal: 1,
		Outputs: []executor.StageOutput{{
			Stage: "discovery", Scanner: "nmap", Raw: []byte("<nmaprun/>")},
		},
	}

	if err := a.Finalize(context.Background(), running, res); err == nil {
		t.Fatal("expected the first terminal status post to fail")
	}
	if err := a.Finalize(context.Background(), running, res); err != nil {
		t.Fatalf("terminal status retry failed: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploads != 1 {
		t.Fatalf("result output was uploaded %d times, want exactly once", f.uploads)
	}
	if len(f.reports) != 2 || f.reports[0].Status != "completed" || f.reports[1].Status != "completed" {
		t.Fatalf("unexpected terminal status attempts: %+v", f.reports)
	}
}

func TestFinalizeBoundsTerminalDiagnosticsToAPISchema(t *testing.T) {
	f := &fakeOrch{}
	a := &Agent{client: f}
	running := &RunningJob{JobID: "bounded-diagnostics-job"}
	long := strings.Repeat("é", maxFailureMessageRunes+100)
	failures := make([]executor.StageFailure, maxTerminalFailureDetails+10)
	for i := range failures {
		failures[i] = executor.StageFailure{
			Code:    strings.Repeat("c", maxFailureCodeRunes+10),
			Stage:   strings.Repeat("s", maxFailureStageRunes+10),
			Plugin:  strings.Repeat("p", maxFailurePluginRunes+10),
			Message: long,
		}
	}
	res := executor.Result{
		JobID: "bounded-diagnostics-job", StagesTotal: 1, StagesFailed: 1,
		Errors: []string{long}, Failures: failures,
	}

	if err := a.Finalize(context.Background(), running, res); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	last := f.reports[len(f.reports)-1]
	f.mu.Unlock()
	if got := utf8.RuneCountInString(last.ErrorMessage); got > maxTerminalErrorMessageRunes {
		t.Fatalf("error_message contains %d runes, max is %d", got, maxTerminalErrorMessageRunes)
	}
	if len(last.FailureDetails) != maxTerminalFailureDetails {
		t.Fatalf("failure_details contains %d entries, max is %d", len(last.FailureDetails), maxTerminalFailureDetails)
	}
	for _, detail := range last.FailureDetails {
		if utf8.RuneCountInString(detail.Code) > maxFailureCodeRunes ||
			utf8.RuneCountInString(detail.Stage) > maxFailureStageRunes ||
			utf8.RuneCountInString(detail.Plugin) > maxFailurePluginRunes ||
			utf8.RuneCountInString(detail.Message) > maxFailureMessageRunes {
			t.Fatalf("unbounded failure detail: %+v", detail)
		}
	}
}

func TestJobDeadlineUsesEarliestSignedOrDurationLimit(t *testing.T) {
	started := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	job := &policy.Job{
		ExpiresAt: started.Add(4 * time.Hour).Format(time.RFC3339),
		Limits:    policy.Limits{MaxDurationSeconds: 30},
	}
	if got, want := jobDeadline(job, started), started.Add(30*time.Second); !got.Equal(want) {
		t.Fatalf("deadline = %s, want duration cap %s", got, want)
	}
	job.Limits.MaxDurationSeconds = 6 * 60 * 60
	if got, want := jobDeadline(job, started), started.Add(4*time.Hour); !got.Equal(want) {
		t.Fatalf("deadline = %s, want signed expiry %s", got, want)
	}
}
