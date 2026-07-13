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

func TestRunHonorsJobMaxDuration(t *testing.T) {
	// A fake nuclei that runs far longer than the job's tiny approved duration
	// must be killed by that deadline — proving the run is bounded by
	// max_duration, not the fixed 30-minute default (which would let it finish).
	w := &Worker{Binary: writeFakeNuclei(t, "exec sleep 5"), Severities: safeSeverities}
	job := &policy.Job{
		JobID:   "j1",
		Targets: []string{"10.0.0.1"},
		Limits:  policy.Limits{MaxDurationSeconds: 1},
	}

	start := time.Now()
	_, err := w.Run(context.Background(), job)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the run to be killed by the 1s max_duration")
	}
	if elapsed > 4*time.Second {
		t.Errorf("max_duration not applied; run took %v (the fake sleeps 5s)", elapsed)
	}
}
