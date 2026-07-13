package nmap

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestBuildArgsSafeProfile(t *testing.T) {
	args, err := BuildArgs(SafeDiscoveryProfile(), "/tmp/out.xml", []string{"10.20.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-sT", "-Pn", "-sV", "-T3", "-p", "-oX", "/tmp/out.xml", "10.20.0.0/24",
		// Gentle-but-not-slothful defaults: trimmed retries and a per-host timeout
		// so dead space and black-hole hosts don't stall the run.
		"--max-retries", "2", "--host-timeout", "15m",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// The default port set must include high-value service ports that --top-ports
	// misses (e.g. Redis 6379), not nmap's frequency ranking.
	if !slices.Contains(args, ImportantPorts) {
		t.Errorf("args missing the important-ports spec: %v", args)
	}
	if !strings.Contains(ImportantPorts, "6379") {
		t.Errorf("ImportantPorts must include Redis 6379: %q", ImportantPorts)
	}
	if slices.Contains(args, "--top-ports") {
		t.Errorf("explicit port set should not also use --top-ports: %v", args)
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

// argValue returns the token following flag in args, or "" if absent.
func argValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

func TestBuildArgsRateFloorStaysUnderCeiling(t *testing.T) {
	// A floor below the ceiling is emitted as-is: the scan won't idle but stays
	// bounded by --max-rate.
	args, err := BuildArgs(Profile{MaxRate: 1000, MinRate: 500}, "/tmp/o.xml", []string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := argValue(args, "--min-rate"); got != "500" {
		t.Errorf("--min-rate = %q, want 500: %v", got, args)
	}
	if got := argValue(args, "--max-rate"); got != "1000" {
		t.Errorf("--max-rate = %q, want 1000: %v", got, args)
	}

	// A floor above the ceiling is clamped down so the scan never exceeds the
	// operator-approved packet rate.
	clamped, err := BuildArgs(Profile{MaxRate: 200, MinRate: 500}, "/tmp/o.xml", []string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := argValue(clamped, "--min-rate"); got != "200" {
		t.Errorf("--min-rate not clamped to ceiling: got %q, want 200: %v", got, clamped)
	}
}

func TestBuildArgsRejectsInvalidHostTimeout(t *testing.T) {
	_, err := BuildArgs(
		Profile{Ports: "80", HostTimeout: "30m; rm -rf /"}, "/tmp/o.xml", []string{"10.0.0.1"},
	)
	if err == nil {
		t.Error("expected rejection of a malformed host-timeout")
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
