package testssl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/codebooker/vulna/scout/internal/discovery"
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

func TestEndpoints(t *testing.T) {
	w := &Worker{Port: 443}
	got := w.endpoints([]string{
		"10.20.0.0/24",   // CIDR: testssl can't scan a range -> skipped
		"10.20.0.5",      // bare IP -> default port
		"10.20.0.5",      // duplicate -> collapsed
		"10.20.0.6:8443", // explicit TLS endpoint -> kept as given
		"evil.com:443",   // hostname:port -> not a literal IP -> skipped
		"10.20.0.7:0",    // invalid port -> skipped
		"-oN",            // flag-like -> skipped
	})
	want := []string{"10.20.0.5:443", "10.20.0.6:8443"}
	if !slices.Equal(got, want) {
		t.Errorf("endpoints = %v, want %v", got, want)
	}
	// A bare IPv6 target is bracketed with the default port.
	if got := w.endpoints([]string{"2001:db8::1"}); !slices.Equal(got, []string{"[2001:db8::1]:443"}) {
		t.Errorf("IPv6 endpoint = %v", got)
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

// writeFakeTestssl installs a stand-in that mimics testssl.sh: it writes a
// one-element JSON array naming the host:port it was given to the --jsonfile
// path, so a multi-host Run can be checked for which endpoints it scanned.
func writeFakeTestssl(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	script := "#!/bin/sh\n" +
		"OUT=\"\"\nprev=\"\"\nLAST=\"\"\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"--jsonfile\" ]; then OUT=\"$a\"; fi\n" +
		"  prev=\"$a\"\n  LAST=\"$a\"\ndone\n" +
		"printf '[{\"target\":\"%s\"}]\\n' \"$LAST\" > \"$OUT\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunScansEveryEndpointAndMerges(t *testing.T) {
	w := &Worker{Binary: writeFakeTestssl(t), Port: 443}
	job := &policy.Job{JobID: "j", Targets: []string{
		"10.0.0.5",      // bare IP -> scanned on 443
		"10.0.0.6:8443", // explicit endpoint -> scanned as given
		"10.0.0.0/24",   // CIDR -> skipped
	}}
	out, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("multi-host scan failed: %v", err)
	}
	var arr []map[string]string
	if err := json.Unmarshal(out, &arr); err != nil {
		t.Fatalf("merged output is not a JSON array: %v: %s", err, out)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 merged results (CIDR skipped), got %d: %s", len(arr), out)
	}
	targets := []string{arr[0]["target"], arr[1]["target"]}
	if !slices.Contains(targets, "10.0.0.5:443") {
		t.Errorf("bare IP was not scanned on the default port: %v", targets)
	}
	if !slices.Contains(targets, "10.0.0.6:8443") {
		t.Errorf("explicit host:port endpoint was not scanned as given: %v", targets)
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

func TestTargetsForReturnsTLSEndpoints(t *testing.T) {
	w := NewWorker()
	eps := []discovery.Endpoint{
		{IP: "10.0.0.1", Port: 443, Transport: "tcp", Service: "https", TLS: true, HTTP: true},
		{IP: "10.0.0.1", Port: 80, Transport: "tcp", Service: "http", HTTP: true}, // not TLS -> excluded
		{IP: "10.0.0.2", Port: 8443, Transport: "tcp", Service: "https", TLS: true},
		{IP: "10.0.0.3", Port: 443, Transport: "udp", TLS: true}, // udp -> excluded
	}
	got := w.TargetsFor(eps)
	want := []string{"10.0.0.1:443", "10.0.0.2:8443"}
	if !slices.Equal(got, want) {
		t.Errorf("TargetsFor = %v, want %v (only TCP TLS endpoints)", got, want)
	}
}
