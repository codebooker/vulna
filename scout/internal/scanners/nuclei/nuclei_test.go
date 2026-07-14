package nuclei

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestBuildArgsSafePolicy(t *testing.T) {
	args := BuildArgs("/tmp/out.jsonl", "/tmp/targets.txt", "", safeSeverities)
	for _, want := range []string{
		"-list", "/tmp/targets.txt", "-jsonl", "-output", "/tmp/out.jsonl",
		"-stats-json", "-no-color", "-disable-update-check", "-exclude-tags", "-severity",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// The excluded-tags value must carry every intrusive/destructive tag.
	i := slices.Index(args, "-exclude-tags")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("no exclude-tags value: %v", args)
	}
	tags := args[i+1]
	for _, tag := range []string{"dos", "intrusive", "fuzzing", "brute-force"} {
		if !strings.Contains(tags, tag) {
			t.Errorf("exclude-tags missing %q: %q", tag, tags)
		}
	}
	sev := args[slices.Index(args, "-severity")+1]
	if sev != "low,medium,high,critical" {
		t.Errorf("unexpected severities: %q", sev)
	}
}

func TestBuildArgsOmitsSeverityWhenEmpty(t *testing.T) {
	args := BuildArgs("/tmp/o.jsonl", "/tmp/t.txt", "", nil)
	if slices.Contains(args, "-severity") {
		t.Errorf("should not pass -severity when none configured: %v", args)
	}
}

func TestBuildArgsPassesTemplatesDir(t *testing.T) {
	args := BuildArgs("/tmp/o.jsonl", "/tmp/t.txt", "/opt/nuclei-templates", safeSeverities)
	i := slices.Index(args, "-templates")
	if i < 0 || i+1 >= len(args) || args[i+1] != "/opt/nuclei-templates" {
		t.Errorf("expected -templates /opt/nuclei-templates in args: %v", args)
	}
	// No templates dir => no -templates flag (nuclei uses its default location).
	if slices.Contains(BuildArgs("/tmp/o.jsonl", "/tmp/t.txt", "", safeSeverities), "-templates") {
		t.Error("should not pass -templates when none configured")
	}
}

func TestRunRejectsFlagLikeTarget(t *testing.T) {
	w := NewWorker()
	job := &policy.Job{JobID: "j1", Targets: []string{"-oN"}}
	if _, err := w.Run(context.Background(), job); err == nil {
		t.Error("expected rejection of a flag-like target")
	}
}

func TestRunRejectsHostnameTarget(t *testing.T) {
	w := NewWorker()
	job := &policy.Job{JobID: "j1", Targets: []string{"example.com"}}
	if _, err := w.Run(context.Background(), job); err == nil {
		t.Error("expected rejection of a non-IP target")
	}
}

func TestRunFailsWithMissingBinary(t *testing.T) {
	w := &Worker{Binary: "definitely-not-a-real-binary-xyz", Severities: safeSeverities}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	out, err := w.Run(context.Background(), job)
	if err == nil {
		t.Fatal("expected an error when the nuclei binary is missing")
	}
	if out != nil {
		t.Errorf("expected no output on failure, got %d bytes", len(out))
	}
}

func TestStageAndName(t *testing.T) {
	w := NewWorker()
	if w.Stage() != "vulnerability" || w.Name() != "nuclei" {
		t.Errorf("unexpected stage/name: %s/%s", w.Stage(), w.Name())
	}
}
