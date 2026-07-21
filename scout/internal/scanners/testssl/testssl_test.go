package testssl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codebooker/vulna/scout/internal/discovery"
	"github.com/codebooker/vulna/scout/internal/policy"
)

func TestBuildArgsAllowlisted(t *testing.T) {
	args := BuildArgs("/tmp/out.json", "10.0.0.1:443")
	for _, want := range []string{
		"--quiet", "--color", "0", "--warnings", "batch",
		"--connect-timeout", "5", "--openssl-timeout", "15",
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

func TestRunFailsWhenTestsslExitsWithoutResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Binary: path, Port: 443}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	if out, err := w.Run(context.Background(), job); err == nil {
		t.Fatalf("failed testssl execution was reported clean: %s", out)
	}
}

func TestRunFailsWhenTestsslExitsZeroWithoutResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Binary: path, Port: 443}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	if out, err := w.Run(context.Background(), job); err == nil {
		t.Fatalf("empty testssl execution was reported clean: %s", out)
	}
}

func TestRunFailsWhenTestsslWritesMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	script := "#!/bin/sh\n" +
		"while [ \"$1\" != \"--jsonfile\" ]; do shift; done\n" +
		"printf 'not-json\\n' > \"$2\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Binary: path, Port: 443}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	if out, err := w.Run(context.Background(), job); err == nil {
		t.Fatalf("malformed testssl output was reported clean: %s", out)
	}
}

func TestRunAcceptsValidJSONWhenTestsslReturnsAggregateCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	script := "#!/bin/sh\n" +
		"while [ \"$1\" != \"--jsonfile\" ]; do shift; done\n" +
		"printf '[{\"id\":\"partial\"}]\\n' > \"$2\"\n" +
		"exit 8\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Binary: path, Port: 443}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	out, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("valid JSON plus aggregate testssl status should succeed: %v", err)
	}
	var records []map[string]string
	if json.Unmarshal(out, &records) != nil || len(records) != 1 || records[0]["id"] != "partial" {
		t.Fatalf("valid partial evidence was lost: %s", out)
	}
}

func TestRunRejectsReservedFatalCodeEvenWithJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	script := "#!/bin/sh\n" +
		"while [ \"$1\" != \"--jsonfile\" ]; do shift; done\n" +
		"printf '[{\"id\":\"scanProblem\",\"severity\":\"FATAL\",\"finding\":\"cannot connect\"}]\\n' > \"$2\"\n" +
		"exit 246\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Binary: path, Port: 443}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	out, err := w.Run(context.Background(), job)
	if err == nil {
		t.Fatal("testssl connectivity failure was reported clean when no endpoint succeeded")
	}
	if !strings.Contains(string(out), `"id":"scanProblem"`) {
		t.Fatalf("valid partial evidence was lost: %s", out)
	}
}

func TestRunFailsOnPerEndpointTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Binary: path, Port: 443, Timeout: 20 * time.Millisecond}
	job := &policy.Job{JobID: "j1", Targets: []string{"10.20.0.5"}}
	if _, err := w.Run(context.Background(), job); err == nil {
		t.Fatal("timed-out testssl execution was reported clean")
	}
}

func TestRunHonorsParentJobCancellationWithConcurrentEndpoints(t *testing.T) {
	w := &Worker{
		Port: 443,
		scanEndpoint: func(ctx context.Context, _ string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	job := &policy.Job{
		JobID:   "cancelled",
		Targets: []string{"10.0.0.1:443", "10.0.0.2:443"},
		Limits:  policy.Limits{MaxParallelHosts: 2},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := w.Run(ctx, job)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want parent deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("parent cancellation took too long: %v", elapsed)
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
		{IP: "10.0.0.4", Port: 3389, Transport: "tcp", Service: "ms-wbt-server", TLS: true},
		{IP: "10.0.0.5", Port: 22, Transport: "tcp", Service: "ssh", TLS: true},
		{IP: "10.0.0.6", Port: 5900, Transport: "tcp", Service: "vnc", TLS: true},
		{IP: "10.0.0.7", Port: 25, Transport: "tcp", Service: "smtp-starttls", TLS: true},
	}
	got := w.TargetsFor(eps)
	want := []string{"10.0.0.1:443", "10.0.0.2:8443"}
	if !slices.Equal(got, want) {
		t.Errorf("TargetsFor = %v, want %v (only TCP TLS endpoints)", got, want)
	}
}

func TestRunUsesSignedParallelLimitAndKeepsTargetOrder(t *testing.T) {
	var active int32
	var maximum int32
	w := &Worker{
		Port: 443,
		scanEndpoint: func(_ context.Context, endpoint string) ([]byte, error) {
			current := atomic.AddInt32(&active, 1)
			for {
				seen := atomic.LoadInt32(&maximum)
				if current <= seen || atomic.CompareAndSwapInt32(&maximum, seen, current) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			return []byte(fmt.Sprintf(`[{"target":%q}]`, endpoint)), nil
		},
	}
	job := &policy.Job{
		JobID: "parallel",
		Targets: []string{
			"10.0.0.1:443", "10.0.0.2:443", "10.0.0.3:443", "10.0.0.4:443",
		},
		Limits: policy.Limits{MaxParallelHosts: 2},
	}
	out, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if maximum != 2 {
		t.Fatalf("maximum parallel scans = %d, want signed limit 2", maximum)
	}
	var records []map[string]string
	if err := json.Unmarshal(out, &records); err != nil {
		t.Fatal(err)
	}
	for i, record := range records {
		if want := fmt.Sprintf("10.0.0.%d:443", i+1); record["target"] != want {
			t.Fatalf("result %d target = %q, want %q", i, record["target"], want)
		}
	}
}

func TestRunToleratesRecoverableFailureWhenAnotherEndpointSucceeds(t *testing.T) {
	w := &Worker{
		Port: 443,
		scanEndpoint: func(_ context.Context, endpoint string) ([]byte, error) {
			if endpoint == "10.0.0.2:443" {
				return nil, &endpointScanError{
					err: errors.New("exit status 246"), recoverable: true,
				}
			}
			return []byte(`[{"id":"usable"}]`), nil
		},
	}
	job := &policy.Job{
		JobID:   "partial",
		Targets: []string{"10.0.0.1:443", "10.0.0.2:443"},
		Limits:  policy.Limits{MaxParallelHosts: 2},
	}
	out, err := w.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("one stale endpoint should not fail useful TLS results: %v", err)
	}
	if string(out) != `[{"id":"usable"}]` {
		t.Fatalf("merged output = %s", out)
	}
}

func TestRunHardFailureStillFailsAlongsideSuccessfulEndpoint(t *testing.T) {
	w := &Worker{
		Port: 443,
		scanEndpoint: func(_ context.Context, endpoint string) ([]byte, error) {
			if endpoint == "10.0.0.2:443" {
				return nil, &endpointScanError{
					err: errors.New("invalid testssl JSON"), recoverable: false,
				}
			}
			return []byte(`[{"id":"usable"}]`), nil
		},
	}
	job := &policy.Job{
		JobID:   "hard-failure",
		Targets: []string{"10.0.0.1:443", "10.0.0.2:443"},
		Limits:  policy.Limits{MaxParallelHosts: 2},
	}
	if _, err := w.Run(context.Background(), job); err == nil {
		t.Fatal("hard scanner corruption was tolerated")
	}
}

func TestRunBoundsEndpointFailureDiagnostics(t *testing.T) {
	w := &Worker{
		Port: 443,
		scanEndpoint: func(_ context.Context, _ string) ([]byte, error) {
			return nil, &endpointScanError{
				err: errors.New("exit status 246"), recoverable: true,
			}
		},
	}
	job := &policy.Job{JobID: "bounded", Limits: policy.Limits{MaxParallelHosts: 3}}
	for i := 1; i <= 7; i++ {
		job.Targets = append(job.Targets, fmt.Sprintf("10.0.0.%d:443", i))
	}
	_, err := w.Run(context.Background(), job)
	if err == nil {
		t.Fatal("all-endpoint failure was reported clean")
	}
	message := err.Error()
	if !strings.Contains(message, "failed on 7 of 7 endpoint(s)") ||
		!strings.Contains(message, "plus 2 more") {
		t.Fatalf("unexpected bounded diagnostic: %s", message)
	}
	if strings.Contains(message, "10.0.0.6:443") {
		t.Fatalf("diagnostic included more than %d samples: %s", maxDiagnosticSamples, message)
	}
}
