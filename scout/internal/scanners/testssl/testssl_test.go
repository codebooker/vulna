package testssl

import (
	"context"
	"slices"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestBuildArgsAllowlisted(t *testing.T) {
	args := BuildArgs("/tmp/out.json", "10.0.0.1:443")
	for _, want := range []string{
		"--quiet", "--color", "0", "--warnings", "batch",
		"--jsonfile", "/tmp/out.json", "10.0.0.1:443",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// The host:port must be the final argument (no flag-like injection).
	if args[len(args)-1] != "10.0.0.1:443" {
		t.Errorf("host:port must be last arg: %v", args)
	}
}

func TestFirstSingleHost(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"10.20.0.0/24", "10.20.0.5", "10.20.0.6"}, "10.20.0.5"},
		{[]string{"10.20.0.0/24"}, ""},
		{nil, ""},
		{[]string{"2001:db8::1"}, "2001:db8::1"},
	}
	for _, c := range cases {
		if got := firstSingleHost(c.in); got != c.want {
			t.Errorf("firstSingleHost(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunNoSingleHostIsNoOp(t *testing.T) {
	w := NewWorker()
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.0/24"}}
	out, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("range-only job should be a no-op, got err %v", err)
	}
	if out != nil {
		t.Errorf("expected no output, got %d bytes", len(out))
	}
}

func TestRunFailsWithMissingBinary(t *testing.T) {
	w := &Worker{Binary: "definitely-not-a-real-binary-xyz", Port: 443}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	out, err := w.Run(context.Background(), job)
	if err == nil {
		t.Fatal("expected an error when the testssl binary is missing")
	}
	if out != nil {
		t.Errorf("expected no output on failure, got %d bytes", len(out))
	}
}

func TestStageAndName(t *testing.T) {
	w := NewWorker()
	if w.Stage() != "tls" || w.Name() != "testssl" {
		t.Errorf("unexpected stage/name: %s/%s", w.Stage(), w.Name())
	}
}
