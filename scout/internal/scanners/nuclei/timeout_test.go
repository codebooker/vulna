package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func writeFakeNuclei(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-nuclei")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunHonorsParentJobDeadline(t *testing.T) {
	// The agent owns the signed, whole-job deadline. A scanner must inherit that
	// context and kill its process promptly when the authorization expires.
	w := &Worker{Binary: writeFakeNuclei(t, "exec sleep 5"), Severities: safeSeverities}
	job := &policy.Job{
		JobID:   "j1",
		Targets: []string{"10.0.0.1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := w.Run(ctx, job)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the run to be killed by the parent job deadline")
	}
	if elapsed > 2*time.Second {
		t.Errorf("parent deadline not applied; run took %v (the fake sleeps 5s)", elapsed)
	}
}

func TestNewWorkerDoesNotImposeInvocationDeadline(t *testing.T) {
	w := NewWorker()
	runCtx, cancel := w.runContext(context.Background())
	defer cancel()
	if deadline, ok := runCtx.Deadline(); ok {
		t.Fatalf("default Nuclei worker imposed a hidden invocation deadline: %s", deadline)
	}

	w.Timeout = 50 * time.Millisecond
	runCtx, cancel = w.runContext(context.Background())
	defer cancel()
	if _, ok := runCtx.Deadline(); !ok {
		t.Fatal("explicit Nuclei timeout override was not applied")
	}
}
