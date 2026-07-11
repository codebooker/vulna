// Package metasploit runs a single authorized Metasploit module against a single
// in-scope target for a controlled-pentest job. It is the exploit engine on the
// probe, kept behind a small Runner interface so the safety logic — single
// target, fail-closed policy re-check, time-box, evidence minimization at the
// edge, and MANDATORY teardown of any live session — is testable without a real
// msfrpcd, and the real client is a thin adapter.
package metasploit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/codebooker/vulna/scout/internal/pentest"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/scanners"
)

// ModuleSpec is one authorized module run against one target.
type ModuleSpec struct {
	Module  string
	Payload string
	Target  string
	Options map[string]any
}

// Session is a live session (shell/Meterpreter) opened by a run; it must be torn
// down before the job is considered complete.
type Session struct{ ID string }

// RunResult is the raw outcome of a module run.
type RunResult struct {
	Evidence map[string]any
	Sessions []Session
	Success  bool
	// CleanupVerified is true only when the runner has confirmed it left no live
	// session behind (e.g. by listing sessions after teardown), or has handed every
	// session it opened back in Sessions for the Worker to stop. It is false when
	// teardown could not be confirmed (timeout, cancel, kill error) — the Worker
	// then reports cleanup as unverified so the dashboard flags it for follow-up
	// instead of falsely claiming the host was cleaned.
	CleanupVerified bool
}

// Runner drives Metasploit (real impl talks to msfrpcd). Kept minimal so the
// worker's safety behavior can be tested with a fake.
type Runner interface {
	RunModule(ctx context.Context, spec ModuleSpec) (RunResult, error)
	StopSession(ctx context.Context, id string) error
}

// Worker runs the controlled-pentest "exploit" stage. It satisfies
// scanners.Scanner.
type Worker struct {
	Runner      Runner
	MaxTimeout  time.Duration // hard cap regardless of the stage's request
	TeardownTTL time.Duration
}

// NewWorker builds a Worker with the given Runner (nil = not configured).
func NewWorker(runner Runner) *Worker {
	return &Worker{Runner: runner, MaxTimeout: 30 * time.Minute, TeardownTTL: 30 * time.Second}
}

func (w *Worker) Stage() string { return "exploit" }
func (w *Worker) Name() string  { return "metasploit" }

func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	spec, maxSecs, err := parseStage(job)
	if err != nil {
		return nil, err
	}
	// Exactly one target; a pentest is a single-host action.
	if len(job.Targets) != 1 {
		return nil, fmt.Errorf("controlled pentest requires exactly one target, got %d", len(job.Targets))
	}
	spec.Target = job.Targets[0]
	if err := scanners.ValidateTarget(spec.Target); err != nil {
		return nil, err
	}
	// Fail-closed local re-check. The signed controlled-pentest job is the
	// authorization (approved + allowExploit); this still blocks DoS and any
	// malformed/disallowed module even if the orchestrator were compromised.
	if err := pentest.ValidateModule(spec.Module, true, true, spec.Payload, spec.Options); err != nil {
		return nil, err
	}
	if w.Runner == nil {
		return nil, errors.New("metasploit runtime is not configured on this scout")
	}

	tctx, cancel := context.WithTimeout(ctx, w.boundedTimeout(maxSecs))
	defer cancel()
	res, runErr := w.Runner.RunModule(tctx, spec)

	// MANDATORY: tear down any session opened, even on error/timeout/cancel, on a
	// fresh context so teardown still runs after the run context expired.
	teardownOK := w.teardown(res.Sessions)

	if runErr != nil {
		return nil, runErr
	}
	// Cleanup is "verified" only when the runner confirmed no live session remains
	// AND every session handed back for the Worker to stop was stopped without
	// error. Anything less is reported unverified so the backend flags it for
	// manual verification rather than claiming the host was cleaned.
	cleanupVerified := res.CleanupVerified && teardownOK
	// Minimize at the edge: proof, not secrets, before anything leaves the site.
	out := map[string]any{
		"module":           spec.Module,
		"target":           spec.Target,
		"success":          res.Success,
		"cleanup_verified": cleanupVerified,
		"evidence":         pentest.Minimize(res.Evidence),
	}
	return json.Marshal(out)
}

func (w *Worker) boundedTimeout(maxSecs int) time.Duration {
	d := w.MaxTimeout
	if maxSecs > 0 {
		if s := time.Duration(maxSecs) * time.Second; s < d {
			d = s
		}
	}
	if d <= 0 {
		d = w.MaxTimeout
	}
	return d
}

// teardown stops every session handed back by the runner and reports whether all
// stops succeeded. No sessions to stop counts as success (the ConsoleRunner tears
// down in-band and returns none); a nil runner or any StopSession error is a
// failure, so the caller does not claim a verified cleanup.
func (w *Worker) teardown(sessions []Session) bool {
	if len(sessions) == 0 {
		return true
	}
	if w.Runner == nil {
		return false
	}
	ttl := w.TeardownTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), ttl)
	defer cancel()
	ok := true
	for _, s := range sessions {
		if err := w.Runner.StopSession(ctx, s.ID); err != nil {
			ok = false
		}
	}
	return ok
}

// parseStage extracts the module spec and time-box from the job's metasploit
// stage config.
func parseStage(job *policy.Job) (ModuleSpec, int, error) {
	for _, stage := range job.Workflow {
		if plugin, _ := stage["plugin"].(string); plugin != "metasploit" {
			continue
		}
		cfg, _ := stage["config"].(map[string]any)
		if cfg == nil {
			return ModuleSpec{}, 0, errors.New("metasploit stage has no config")
		}
		module, _ := cfg["module"].(string)
		if module == "" {
			return ModuleSpec{}, 0, errors.New("metasploit stage has no module")
		}
		payload, _ := cfg["payload"].(string)
		options, _ := cfg["options"].(map[string]any)
		maxSecs := 0
		switch v := cfg["max_session_seconds"].(type) {
		case float64:
			maxSecs = int(v)
		case int:
			maxSecs = v
		}
		return ModuleSpec{Module: module, Payload: payload, Options: options}, maxSecs, nil
	}
	return ModuleSpec{}, 0, errors.New("job has no metasploit stage")
}
