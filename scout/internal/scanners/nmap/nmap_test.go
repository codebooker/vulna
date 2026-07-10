package nmap

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestBuildArgsSafeProfile(t *testing.T) {
	args, err := BuildArgs(SafeDiscoveryProfile(), "/tmp/out.xml", []string{"10.20.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-sT", "-sV", "-T3", "--top-ports", "100", "-oX", "/tmp/out.xml", "10.20.0.0/24"} {
		if !slices.Contains(args, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// No raw-socket scan types (unprivileged agent).
	for _, bad := range []string{"-sS", "-sU", "-O", "--script"} {
		if slices.Contains(args, bad) {
			t.Errorf("args unexpectedly contain %q", bad)
		}
	}
}

func TestBuildArgsRejectsFlagLikeTarget(t *testing.T) {
	// A target that looks like an nmap flag must be rejected (argument injection).
	for _, bad := range []string{"-oN", "--script=http-vuln", "-sS"} {
		if _, err := BuildArgs(SafeDiscoveryProfile(), "/tmp/o.xml", []string{bad}); err == nil {
			t.Errorf("expected rejection of flag-like target %q", bad)
		}
	}
}

func TestBuildArgsRejectsInvalidTarget(t *testing.T) {
	if _, err := BuildArgs(SafeDiscoveryProfile(), "/tmp/o.xml", []string{"example.com"}); err == nil {
		t.Error("hostnames are not valid targets for discovery args")
	}
	if _, err := BuildArgs(SafeDiscoveryProfile(), "/tmp/o.xml", []string{"10.0.0.1; rm -rf /"}); err == nil {
		t.Error("expected rejection of shell-metachar target")
	}
}

func TestBuildArgsClampsTimingAndRate(t *testing.T) {
	p := Profile{TopPorts: 10, Timing: 9, MaxRate: 500, ServiceDetection: false}
	args, err := BuildArgs(p, "/tmp/o.xml", []string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "-T4") { // 9 clamped to 4
		t.Errorf("timing not clamped: %v", args)
	}
	if !slices.Contains(args, "--max-rate") || !slices.Contains(args, "500") {
		t.Errorf("max-rate missing: %v", args)
	}
	if slices.Contains(args, "-sV") {
		t.Errorf("service detection should be off: %v", args)
	}
}

// TestWorkerRunAgainstLoopback exercises the real nmap adapter end to end. It is
// opt-in (VULNASCOUT_NMAP_INTEGRATION=1) and skips if nmap is not installed, so
// it never runs in CI. Set VULNASCOUT_NMAP_OUT to write the XML for inspection.
func TestWorkerRunAgainstLoopback(t *testing.T) {
	if os.Getenv("VULNASCOUT_NMAP_INTEGRATION") != "1" {
		t.Skip("set VULNASCOUT_NMAP_INTEGRATION=1 to run the real-nmap integration test")
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not on PATH")
	}
	w := NewWorker()
	w.Profile.TopPorts = 200
	job := &policy.Job{JobID: "loopback", Targets: []string{"127.0.0.1"}}
	xml, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("real nmap run failed: %v", err)
	}
	if !bytes.Contains(xml, []byte("<nmaprun")) {
		t.Fatalf("output is not nmap XML: %.120s", xml)
	}
	if w.Stage() != "discovery" || w.Name() != "nmap" {
		t.Errorf("unexpected stage/name: %s/%s", w.Stage(), w.Name())
	}
	if out := os.Getenv("VULNASCOUT_NMAP_OUT"); out != "" {
		if err := os.WriteFile(out, xml, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkerRunFailsWithMissingBinary(t *testing.T) {
	w := &Worker{Binary: "definitely-not-a-real-binary-xyz", Profile: SafeDiscoveryProfile()}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	out, err := w.Run(context.Background(), job)
	if err == nil {
		t.Fatal("expected an error when the nmap binary is missing")
	}
	if out != nil {
		t.Errorf("expected no output on failure, got %d bytes", len(out))
	}
}
