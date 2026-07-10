package scanners

import (
	"context"
	"errors"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestValidateTarget(t *testing.T) {
	ok := []string{"10.20.0.5", "10.20.0.0/24", "2001:db8::1", "2001:db8::/32"}
	for _, tgt := range ok {
		if err := ValidateTarget(tgt); err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", tgt, err)
		}
	}
	bad := []string{"-oN", "--script=x", "example.com", "10.0.0.1; rm -rf /", ""}
	for _, tgt := range bad {
		if err := ValidateTarget(tgt); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error", tgt)
		}
	}
}

// stubScanner is a configurable Scanner for exercising the workflow runner.
type stubScanner struct {
	stage string
	name  string
	raw   []byte
	err   error
	ran   *bool
}

func (s stubScanner) Stage() string { return s.stage }
func (s stubScanner) Name() string  { return s.name }
func (s stubScanner) Run(_ context.Context, _ *policy.Job) ([]byte, error) {
	if s.ran != nil {
		*s.ran = true
	}
	return s.raw, s.err
}

func jobWith(plugins ...string) *policy.Job {
	wf := make([]map[string]any, 0, len(plugins))
	for _, p := range plugins {
		wf = append(wf, map[string]any{"plugin": p})
	}
	return &policy.Job{JobID: "j1", Workflow: wf}
}

func TestWorkflowCollectsOutputsInOrder(t *testing.T) {
	wf := NewWorkflow(
		stubScanner{stage: "discovery", name: "nmap", raw: []byte("xml")},
		stubScanner{stage: "vulnerability", name: "nuclei", raw: []byte("jsonl")},
	)
	res, err := wf.Run(context.Background(), jobWith("nmap", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	if res.StagesRun != 2 || res.StagesTotal != 2 {
		t.Errorf("unexpected stage counts: %+v", res)
	}
	if len(res.Outputs) != 2 ||
		res.Outputs[0].Scanner != "nmap" || string(res.Outputs[0].Raw) != "xml" ||
		res.Outputs[1].Scanner != "nuclei" || string(res.Outputs[1].Raw) != "jsonl" {
		t.Errorf("outputs not collected in order: %+v", res.Outputs)
	}
}

func TestWorkflowSkipsUnknownPlugin(t *testing.T) {
	ran := false
	wf := NewWorkflow(stubScanner{stage: "discovery", name: "nmap", raw: []byte("xml"), ran: &ran})
	res, err := wf.Run(context.Background(), jobWith("nmap", "unregistered"))
	if err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Error("registered plugin should have run")
	}
	if res.StagesRun != 1 {
		t.Errorf("only the registered stage should run: %+v", res)
	}
	if res.StagesTotal != 2 {
		t.Errorf("StagesTotal should reflect the whole workflow: %+v", res)
	}
}

func TestWorkflowContinuesOnStageError(t *testing.T) {
	wf := NewWorkflow(
		stubScanner{stage: "discovery", name: "nmap", err: errors.New("boom")},
		stubScanner{stage: "vulnerability", name: "nuclei", raw: []byte("jsonl")},
	)
	res, err := wf.Run(context.Background(), jobWith("nmap", "nuclei"))
	if err != nil {
		t.Fatalf("a failed stage must not fail the workflow: %v", err)
	}
	if res.StagesRun != 1 || len(res.Outputs) != 1 || res.Outputs[0].Scanner != "nuclei" {
		t.Errorf("expected only nuclei output: %+v", res)
	}
}

func TestWorkflowStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wf := NewWorkflow(stubScanner{stage: "discovery", name: "nmap", raw: []byte("xml")})
	res, err := wf.Run(ctx, jobWith("nmap"))
	if err == nil {
		t.Fatal("expected a cancellation error")
	}
	if !res.Cancelled {
		t.Errorf("result should be marked cancelled: %+v", res)
	}
}
