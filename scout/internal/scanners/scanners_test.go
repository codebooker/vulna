package scanners

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/codebooker/vulna/scout/internal/executor"
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
	if len(res.Outputs) != 4 ||
		res.Outputs[0].Scanner != "nmap" || string(res.Outputs[0].Raw) != "xml" ||
		!res.Outputs[1].Complete ||
		res.Outputs[2].Scanner != "nuclei" || string(res.Outputs[2].Raw) != "jsonl" ||
		!res.Outputs[3].Complete {
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
	if res.StagesRun != 1 || len(res.Outputs) != 2 ||
		res.Outputs[0].Scanner != "nuclei" || !res.Outputs[1].Complete {
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

func TestWorkflowRecordsSkippedStages(t *testing.T) {
	// A job whose only stage has no installed scanner runs nothing and records it.
	wf := NewWorkflow() // no scanners registered
	res, err := wf.Run(context.Background(), jobWith("nmap"))
	if err != nil {
		t.Fatal(err)
	}
	if res.StagesRun != 0 || res.StagesSkipped != 1 {
		t.Errorf("expected 0 run / 1 skipped, got run=%d skipped=%d", res.StagesRun, res.StagesSkipped)
	}
	if len(res.Errors) == 0 {
		t.Error("a skipped stage must be recorded, not silently swallowed")
	}
}

func TestWorkflowRecordsScannerErrors(t *testing.T) {
	wf := NewWorkflow(
		stubScanner{stage: "discovery", name: "nmap", raw: []byte("xml")},
		stubScanner{stage: "vulnerability", name: "nuclei", err: errTest},
	)
	res, err := wf.Run(context.Background(), jobWith("nmap", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	if res.StagesRun != 1 || res.StagesFailed != 1 {
		t.Errorf("expected 1 run / 1 failed, got run=%d failed=%d", res.StagesRun, res.StagesFailed)
	}
	if len(res.Failures) != 1 || res.Failures[0].Code != "scanner_error" ||
		res.Failures[0].Plugin != "nuclei" {
		t.Errorf("expected structured nuclei failure, got %+v", res.Failures)
	}
}

func TestWorkflowReportsHonestStageProgress(t *testing.T) {
	wf := NewWorkflow(
		stubScanner{stage: "discovery", name: "nmap", raw: []byte("xml")},
		stubScanner{stage: "vulnerability", name: "nuclei", raw: []byte("jsonl")},
	)
	job := jobWith("nmap", "nuclei")
	job.Targets = []string{"10.20.0.0/30"}
	var reports []executor.Progress
	res, err := wf.RunWithProgress(context.Background(), job, func(progress executor.Progress) {
		reports = append(reports, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 4 || res.StagesRun != 2 {
		t.Fatalf("unexpected progress count/result: reports=%d result=%+v", len(reports), res)
	}
	if reports[0].Percent != 0 || reports[1].Percent != 50 || reports[3].Percent != 99 {
		t.Errorf("percent must follow completed stages, got %+v", reports)
	}
	if reports[1].ETASeconds == nil || reports[1].TargetAddresses != 4 {
		t.Errorf("expected evidence-backed ETA and target stats, got %+v", reports[1])
	}
}

var errTest = fmtError("scanner exploded")

type fmtError string

func (e fmtError) Error() string { return string(e) }

// recordingScanner captures the targets it was invoked with, so a test can prove
// the workflow partitioned the job into distinct chunks.
type recordingScanner struct {
	stage, name string
	raw         []byte
	seen        *[][]string
}

func (s recordingScanner) Stage() string { return s.stage }
func (s recordingScanner) Name() string  { return s.name }
func (s recordingScanner) Run(_ context.Context, job *policy.Job) ([]byte, error) {
	*s.seen = append(*s.seen, append([]string(nil), job.Targets...))
	return s.raw, nil
}

func TestRunStreamingEmitsPerChunk(t *testing.T) {
	var seen [][]string
	wf := NewWorkflow(recordingScanner{stage: "discovery", name: "nmap", raw: []byte("xml"), seen: &seen})
	job := jobWith("nmap")
	job.Targets = []string{"10.0.0.0/23"} // two /24s -> two chunks at 256/chunk

	var sunk []executor.StageOutput
	res, err := wf.RunStreaming(context.Background(), job, nil, func(o executor.StageOutput) error {
		sunk = append(sunk, o)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("expected 2 chunk runs, got %d: %v", len(seen), seen)
	}
	if len(seen[0]) == 0 || len(seen[1]) == 0 || seen[0][0] == seen[1][0] {
		t.Errorf("chunks were not distinct sub-ranges: %v", seen)
	}
	if len(sunk) != 3 || !sunk[2].Complete {
		t.Errorf("expected 2 streamed outputs followed by completion, got %+v", sunk)
	}
	if len(res.Outputs) != 0 {
		t.Errorf("streamed output must not also be carried in the Result: %+v", res.Outputs)
	}
	if res.StagesRun != 1 || res.StagesTotal != 1 {
		t.Errorf("unexpected stage counts: %+v", res)
	}
}

func TestRunStreamingCarriesOutputWhenSinkRejects(t *testing.T) {
	wf := NewWorkflow(stubScanner{stage: "discovery", name: "nmap", raw: []byte("xml")})
	job := jobWith("nmap")
	job.Targets = []string{"10.0.0.0/24"} // single chunk

	var attempted []executor.StageOutput
	res, err := wf.RunStreaming(context.Background(), job, nil, func(out executor.StageOutput) error {
		attempted = append(attempted, out)
		if len(out.Raw) > 0 {
			return errors.New("queue full")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outputs) != 2 || !res.Outputs[1].Complete {
		t.Errorf("a rejected batch and completion must be carried in the Result: %+v", res.Outputs)
	}
	if len(attempted) != 1 || attempted[0].Complete {
		t.Errorf("completion must not bypass a rejected result batch: %+v", attempted)
	}
	if res.StagesRun != 1 {
		t.Errorf("stage should still count as run: %+v", res)
	}
}

func TestRunStreamingFailsStageOnScannerError(t *testing.T) {
	wf := NewWorkflow(stubScanner{stage: "discovery", name: "nmap", err: errors.New("boom")})
	job := jobWith("nmap")
	job.Targets = []string{"10.0.0.0/23"} // two chunks; the error is recorded once

	res, err := wf.RunStreaming(context.Background(), job, nil, func(executor.StageOutput) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if res.StagesFailed != 1 || res.StagesRun != 0 {
		t.Errorf("expected the stage to be failed once: %+v", res)
	}
	if len(res.Failures) != 1 {
		t.Errorf("expected a single stage failure across chunks, got %d: %+v", len(res.Failures), res.Failures)
	}
}

// streamingStub is a Scanner that also implements Streamer, emitting one batch
// per host so a test can prove RunStreaming prefers per-host delivery.
type streamingStub struct {
	stage, name string
	hosts       [][]byte
}

func (s streamingStub) Stage() string { return s.stage }
func (s streamingStub) Name() string  { return s.name }
func (s streamingStub) Run(context.Context, *policy.Job) ([]byte, error) {
	return bytes.Join(s.hosts, nil), nil
}
func (s streamingStub) Stream(
	_ context.Context, _ *policy.Job, sink func([]byte) error, progress func(int),
) error {
	for i, h := range s.hosts {
		if err := sink(h); err != nil {
			return err
		}
		progress(i + 1)
	}
	return nil
}

func TestRunStreamingUsesStreamerForPerHostDelivery(t *testing.T) {
	hosts := [][]byte{[]byte("h1"), []byte("h2"), []byte("h3")}
	wf := NewWorkflow(streamingStub{stage: "discovery", name: "nmap", hosts: hosts})
	job := jobWith("nmap")
	job.Targets = []string{"10.0.0.0/24"} // single chunk

	var sunk [][]byte
	res, err := wf.RunStreaming(context.Background(), job, nil, func(o executor.StageOutput) error {
		sunk = append(sunk, o.Raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sunk) != 4 || sunk[3] != nil {
		t.Errorf("expected 3 per-host emissions and completion, got %d: %v", len(sunk), sunk)
	}
	if len(res.Outputs) != 0 {
		t.Errorf("streamed output must not also be carried in the Result: %+v", res.Outputs)
	}
	if res.StagesRun != 1 || res.StagesTotal != 1 {
		t.Errorf("unexpected stage counts: %+v", res)
	}
}

// Without a sink (the collect path), a Streamer must fall back to Run so callers
// that don't stream still get the whole output in the Result.
func TestRunStreamingStreamerFallsBackWithoutSink(t *testing.T) {
	wf := NewWorkflow(streamingStub{stage: "discovery", name: "nmap", hosts: [][]byte{[]byte("h1")}})
	job := jobWith("nmap")
	job.Targets = []string{"10.0.0.0/24"}

	res, err := wf.RunStreaming(context.Background(), job, nil, nil) // nil sink
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outputs) != 2 || !res.Outputs[1].Complete || res.StagesRun != 1 {
		t.Errorf("expected the whole output collected via Run fallback: %+v", res)
	}
}

func TestWorkflowPreservesPartialOutputWhenScannerFails(t *testing.T) {
	wf := NewWorkflow(stubScanner{
		stage: "tls", name: "testssl", raw: []byte("partial"), err: errors.New("one host failed"),
	})
	res, err := wf.Run(context.Background(), jobWith("testssl"))
	if err != nil {
		t.Fatal(err)
	}
	if res.StagesFailed != 1 || len(res.Outputs) != 1 || string(res.Outputs[0].Raw) != "partial" {
		t.Fatalf("partial evidence should be retained with the failure: %+v", res)
	}
}
