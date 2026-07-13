package metasploit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

const reviewedExploit = "exploit/windows/smb/ms17_010_eternalblue"

type fakeRunner struct {
	result   RunResult
	runErr   error
	ran      bool
	stopped  []string
	blockFor time.Duration
	stopErr  error
}

func (f *fakeRunner) RunModule(ctx context.Context, spec ModuleSpec) (RunResult, error) {
	f.ran = true
	if f.blockFor > 0 {
		select {
		case <-time.After(f.blockFor):
		case <-ctx.Done():
			return f.result, ctx.Err()
		}
	}
	return f.result, f.runErr
}

func (f *fakeRunner) StopSession(ctx context.Context, id string) error {
	f.stopped = append(f.stopped, id)
	return f.stopErr
}

func job(module string, targets []string) *policy.Job {
	return &policy.Job{
		JobID: "j1", Mode: "controlled_pentest", Targets: targets,
		Workflow: []map[string]any{
			{"plugin": "metasploit", "config": map[string]any{
				"module": module, "max_session_seconds": float64(60),
			}},
		},
	}
}

func TestRunSuccess(t *testing.T) {
	fr := &fakeRunner{result: RunResult{
		Success:         true,
		CleanupVerified: true,
		Sessions:        []Session{{ID: "s1"}, {ID: "s2"}},
		Evidence: map[string]any{
			"loot": []any{map[string]any{"username": "jimothy", "password": "hunter2"}},
		},
	}}
	w := NewWorker(fr)
	out, err := w.Run(context.Background(), job(reviewedExploit, []string{"10.20.0.5"}))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// Every opened session was torn down.
	if len(fr.stopped) != 2 {
		t.Errorf("expected both sessions torn down, got %v", fr.stopped)
	}
	// Evidence was minimized before leaving: no plaintext password.
	if strings.Contains(string(out), "hunter2") {
		t.Errorf("secret leaked into evidence: %s", out)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["module"] != "exploit/windows/smb/ms17_010_eternalblue" || parsed["success"] != true {
		t.Errorf("unexpected evidence: %v", parsed)
	}
	// Runner verified teardown AND all Worker stops succeeded -> cleanup verified.
	if parsed["cleanup_verified"] != true {
		t.Errorf("expected cleanup_verified true, got %v", parsed["cleanup_verified"])
	}
}

func TestRunReportsUnverifiedCleanupWhenStopFails(t *testing.T) {
	// The runner opened a session and claims verified, but the Worker's teardown
	// stop fails: cleanup must be reported UNVERIFIED so the backend flags it rather
	// than claiming the host was cleaned.
	fr := &fakeRunner{
		result:  RunResult{Success: true, CleanupVerified: true, Sessions: []Session{{ID: "s1"}}},
		stopErr: errors.New("kill failed"),
	}
	w := NewWorker(fr)
	out, err := w.Run(context.Background(), job(reviewedExploit, []string{"10.20.0.5"}))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["cleanup_verified"] != false {
		t.Errorf("expected cleanup_verified false when a stop fails, got %v", parsed["cleanup_verified"])
	}
}

func TestRunRejectsMultipleTargets(t *testing.T) {
	fr := &fakeRunner{}
	w := NewWorker(fr)
	_, err := w.Run(context.Background(), job(reviewedExploit, []string{"10.20.0.5", "10.20.0.6"}))
	if err == nil {
		t.Fatal("multiple targets must be rejected")
	}
	if fr.ran {
		t.Error("the runner must not run for an invalid job")
	}
}

func TestRunBlocksDoSModule(t *testing.T) {
	fr := &fakeRunner{}
	w := NewWorker(fr)
	_, err := w.Run(context.Background(), job("auxiliary/dos/tcp/synflood", []string{"10.20.0.5"}))
	if err == nil || fr.ran {
		t.Fatal("a DoS module must be blocked before the runner is invoked")
	}
}

func TestRunNotConfigured(t *testing.T) {
	w := NewWorker(nil)
	_, err := w.Run(context.Background(), job(reviewedExploit, []string{"10.20.0.5"}))
	if err == nil {
		t.Fatal("a scout with no metasploit runtime must error, not silently succeed")
	}
}

func TestTeardownRunsEvenOnRunError(t *testing.T) {
	fr := &fakeRunner{
		result: RunResult{Sessions: []Session{{ID: "s1"}}},
		runErr: errors.New("module failed"),
	}
	w := NewWorker(fr)
	_, err := w.Run(context.Background(), job(reviewedExploit, []string{"10.20.0.5"}))
	if err == nil {
		t.Fatal("a run error must surface")
	}
	if len(fr.stopped) != 1 {
		t.Errorf("session must be torn down even on error, got %v", fr.stopped)
	}
}

func TestRunTimeBoxedAndTornDown(t *testing.T) {
	fr := &fakeRunner{blockFor: 5 * time.Second, result: RunResult{Sessions: []Session{{ID: "s1"}}}}
	w := NewWorker(fr)
	w.MaxTimeout = 30 * time.Millisecond // hard cap below the runner's block
	start := time.Now()
	if _, err := w.Run(context.Background(), job(reviewedExploit, []string{"10.20.0.5"})); err == nil {
		t.Fatal("expected a time-box error")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the run must be time-boxed, not run to completion")
	}
	if len(fr.stopped) != 1 {
		t.Error("a session opened before the time-box must still be torn down")
	}
}
