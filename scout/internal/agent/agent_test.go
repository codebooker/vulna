package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codebooker/vulna/scout/internal/api"
	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/queue"
	"github.com/codebooker/vulna/scout/internal/storage"
)

// Cross-language vectors: one Python key signed both a policy and a job whose
// target (10.20.0.5/32) is within the policy scope (10.20.0.0/24).
const (
	agentPub    = "blvaFuR83ZFZ+AxnSh49WCQWagd2LnnMKaIdZldONJ0="
	agentPolicy = `{"policy_version": 4, "probe_id": "p1", "site_id": "s1", "approved_cidrs": ["10.20.0.0/24"], "denied_cidrs": [], "allow_public_addresses": false, "allowed_modes": ["vulnerability_assessment"], "allowed_plugins": ["nmap"], "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "Roi9CK9tIdbT2emeUi1S7HQu+/j1Vxh6mjCbZciPlgsCgefulC1RXCH2LNKb0yZHZDOoh2tRlLjFANaqfVhLAA=="}`
	agentJob    = `{"job_id": "job-123", "probe_id": "p1", "site_id": "s1", "mode": "vulnerability_assessment", "policy_version": 4, "not_before": "2020-01-01T00:00:00+00:00", "expires_at": "2030-01-01T00:00:00+00:00", "targets": ["10.20.0.5/32"], "workflow": [{"stage": "discovery", "plugin": "nmap", "config": {}}], "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "XXQ96+bIc576ZxinQFEpmstjEUF7DKTKPsKphVjVwfJj05xOyV0Ze+977nTS7noPHUVHXM3x2/RzNfDIdO6NAQ=="}`
)

type fakeOrch struct {
	mu        sync.Mutex
	policy    []byte
	job       []byte
	jobServed bool
	reports   []api.JobStatusReport
	uploads   int
	uploaded  []byte
	uploadErr error // when set, uploads fail (simulates an offline link)
}

func (f *fakeOrch) FetchPolicy(context.Context) ([]byte, error) { return f.policy, nil }

func (f *fakeOrch) UploadResults(
	_ context.Context, _ string, raw []byte, _, _ string, _ ...bool,
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

func (f *fakeOrch) PollJob(context.Context) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jobServed || f.job == nil {
		return nil, false, nil
	}
	f.jobServed = true
	return f.job, true, nil
}

func (f *fakeOrch) ReportJobStatus(_ context.Context, _ string, r api.JobStatusReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
	return nil
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
