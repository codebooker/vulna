// Package testssl adapts testssl.sh for VulnaScout's TLS stage.
//
// testssl.sh scans one host:port at a time. Only allowlisted, typed arguments
// are passed, with conservative, non-interactive settings (build plan
// Section 12.6).
package testssl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codebooker/vulna/scout/internal/discovery"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/processutil"
)

const (
	defaultBinary         = "testssl.sh"
	defaultTimeout        = 5 * time.Minute
	defaultPort           = 443
	connectTimeoutSeconds = 5
	opensslTimeoutSeconds = 15
	maxDiagnosticSamples  = 5
)

// BuildArgs builds allowlisted testssl.sh arguments for one host:port, writing
// JSON to outPath.
func BuildArgs(outPath, hostPort string) []string {
	return []string{
		"--quiet",
		"--color", "0",
		"--warnings", "batch",
		// testssl.sh otherwise permits individual socket/OpenSSL operations to
		// hang. These are tool-supported bounds, separate from the per-endpoint
		// context deadline below.
		"--connect-timeout", strconv.Itoa(connectTimeoutSeconds),
		"--openssl-timeout", strconv.Itoa(opensslTimeoutSeconds),
		"--jsonfile", outPath,
		hostPort,
	}
}

// endpoints returns the host:port TLS endpoints to scan, one per target that
// testssl.sh can actually handle. A bare IP becomes ip:defaultPort; a host:port
// target (an IP with an explicit port, e.g. a discovered TLS service) is kept as
// given. CIDRs and anything else are skipped — testssl.sh scans a single
// host:port at a time, not a range. Duplicates are collapsed.
func (w *Worker) endpoints(targets []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(host, port string) {
		if _, err := netip.ParseAddr(host); err != nil {
			return // only literal IPs — never a flag-like or hostname value
		}
		ep := net.JoinHostPort(host, port)
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	for _, t := range targets {
		if _, err := netip.ParseAddr(t); err == nil {
			add(t, strconv.Itoa(w.port()))
			continue
		}
		if host, port, err := net.SplitHostPort(t); err == nil {
			if p, err := strconv.Atoi(port); err == nil && p > 0 && p <= 65535 {
				add(host, port)
			}
			continue
		}
		// CIDR / range / other: not a single host:port testssl can scan — skip.
	}
	return out
}

// Worker runs testssl.sh scans. It satisfies scanners.Scanner.
type Worker struct {
	Binary  string
	Timeout time.Duration
	Port    int
	// scanEndpoint is a test seam for exercising concurrency and aggregation
	// without launching real testssl.sh processes.
	scanEndpoint func(context.Context, string) ([]byte, error)
}

// NewWorker returns a Worker with defaults (port 443).
func NewWorker() *Worker {
	return &Worker{Binary: defaultBinary, Timeout: defaultTimeout, Port: defaultPort}
}

func (w *Worker) Stage() string { return "tls" }
func (w *Worker) Name() string  { return "testssl" }

// TargetsFor returns the discovered TLS endpoints as host:port targets, so the
// TLS stage scans the services discovery actually found TLS on (on their real
// ports) instead of the raw address range. When discovery found no TLS the
// result is empty and the executor falls back to the range (a no-op for a CIDR).
func (w *Worker) TargetsFor(endpoints []discovery.Endpoint) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range endpoints {
		if !supportsDirectTLS(e) {
			continue
		}
		addr := e.Addr()
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// supportsDirectTLS rejects encrypted services whose TLS negotiation is not a
// direct ClientHello on connect. testssl.sh can assess HTTPS and implicit TLS
// services on arbitrary ports, but it cannot speak RDP, SSH, VNC, or an
// application-specific STARTTLS preamble before beginning its TLS checks.
func supportsDirectTLS(e discovery.Endpoint) bool {
	if !e.TLS || e.Transport != "tcp" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(e.Service))
	for _, unsupported := range []string{
		"ms-wbt-server", "rdp", "ssh", "vnc", "tcpwrapped", "starttls",
	} {
		if strings.Contains(name, unsupported) {
			return false
		}
	}
	// RDP always performs its own negotiation before TLS. Nmap can report the
	// tunnel as ssl even when its service name is absent or ambiguous.
	return e.Port != 3389
}

func (w *Worker) binary() string {
	if w.Binary != "" {
		return w.Binary
	}
	return defaultBinary
}

func (w *Worker) timeout() time.Duration {
	if w.Timeout > 0 {
		return w.Timeout
	}
	return defaultTimeout
}

func (w *Worker) port() int {
	if w.Port > 0 {
		return w.Port
	}
	return defaultPort
}

// Run scans the TLS of every single-host endpoint in the job and returns the
// merged JSON. Endpoint scans run concurrently up to the job's signed
// max_parallel_hosts limit, while results are merged in target order for stable
// ingestion. Recoverable endpoint drift (a service closing or timing out after
// discovery) does not fail an otherwise useful stage; hard local/tool errors and
// a run where every endpoint failed remain terminal.
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	endpoints := w.endpoints(job.Targets)
	if len(endpoints) == 0 {
		return nil, nil
	}

	type task struct {
		index    int
		endpoint string
	}
	type result struct {
		index int
		data  []byte
		err   error
	}
	tasks := make(chan task)
	results := make(chan result, len(endpoints))
	parallel := job.Limits.MaxParallelHosts
	if parallel <= 0 {
		parallel = 1
	}
	if parallel > len(endpoints) {
		parallel = len(endpoints)
	}

	var workers sync.WaitGroup
	workers.Add(parallel)
	for range parallel {
		go func() {
			defer workers.Done()
			for item := range tasks {
				if ctx.Err() != nil {
					return
				}
				data, err := w.runEndpoint(ctx, item.endpoint)
				results <- result{index: item.index, data: data, err: err}
			}
		}()
	}
	go func() {
		defer close(tasks)
		for i, endpoint := range endpoints {
			select {
			case tasks <- task{index: i, endpoint: endpoint}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	ordered := make([]result, len(endpoints))
	completed := make([]bool, len(endpoints))
	for item := range results {
		ordered[item.index] = item
		completed[item.index] = true
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var parts [][]byte
	var failures []endpointFailure
	succeeded := 0
	hardFailure := false
	for i, item := range ordered {
		if !completed[i] {
			continue
		}
		if len(item.data) > 0 {
			parts = append(parts, item.data)
		}
		if item.err == nil {
			succeeded++
			continue
		}
		if errors.Is(item.err, exec.ErrNotFound) {
			return nil, fmt.Errorf("testssl.sh unavailable: %w", item.err)
		}
		if !isRecoverableEndpointError(item.err) {
			hardFailure = true
		}
		failures = append(failures, endpointFailure{endpoint: endpoints[i], err: item.err})
	}
	merged := mergeJSONArrays(parts)
	if len(failures) == 0 {
		return merged, nil
	}
	failureSummary := summarizeEndpointFailures(failures, len(endpoints), succeeded)
	if succeeded > 0 && !hardFailure {
		// Preserve visibility without turning ordinary post-discovery endpoint
		// drift into a failed assessment. The dashboard receives the successful
		// evidence; operators can inspect the Scout log for this bounded summary.
		log.Printf("testssl completed with recoverable endpoint errors: %v", failureSummary)
		return merged, nil
	}
	return merged, failureSummary
}

type endpointFailure struct {
	endpoint string
	err      error
}

type endpointScanError struct {
	err         error
	recoverable bool
}

func (e *endpointScanError) Error() string { return e.err.Error() }
func (e *endpointScanError) Unwrap() error { return e.err }

func isRecoverableEndpointError(err error) bool {
	var scanErr *endpointScanError
	return errors.As(err, &scanErr) && scanErr.recoverable
}

func summarizeEndpointFailures(failures []endpointFailure, total, succeeded int) error {
	samples := make([]string, 0, min(len(failures), maxDiagnosticSamples))
	for _, failure := range failures[:min(len(failures), maxDiagnosticSamples)] {
		samples = append(samples, fmt.Sprintf("%s: %v", failure.endpoint, failure.err))
	}
	remaining := ""
	if omitted := len(failures) - len(samples); omitted > 0 {
		remaining = fmt.Sprintf("; plus %d more", omitted)
	}
	return fmt.Errorf(
		"testssl failed on %d of %d endpoint(s) (%d succeeded); samples: %s%s",
		len(failures), total, succeeded, strings.Join(samples, "; "), remaining,
	)
}

func (w *Worker) runEndpoint(ctx context.Context, hostPort string) ([]byte, error) {
	if w.scanEndpoint != nil {
		return w.scanEndpoint(ctx, hostPort)
	}
	return w.scanOne(ctx, hostPort)
}

// scanOne runs testssl.sh against a single host:port and returns its raw JSON.
func (w *Worker) scanOne(ctx context.Context, hostPort string) ([]byte, error) {
	// testssl.sh will not overwrite an existing --jsonfile, so hand it a fresh
	// path inside a temp dir rather than a pre-created file.
	dir, err := os.MkdirTemp("", "vulnascout-testssl-*")
	if err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	outPath := filepath.Join(dir, "testssl.json")

	args := BuildArgs(outPath, hostPort)
	runCtx, cancel := context.WithTimeout(ctx, w.timeout())
	defer cancel()
	cmd := processutil.CommandContext(runCtx, w.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if runCtx.Err() != nil {
		return nil, &endpointScanError{err: runCtx.Err(), recoverable: true}
	}
	data, _ := os.ReadFile(outPath)
	if len(data) == 0 {
		if runErr != nil {
			return nil, classifyExecutionError(runErr)
		}
		return nil, &endpointScanError{
			err: fmt.Errorf("testssl produced no JSON output"), recoverable: false,
		}
	}
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, &endpointScanError{
			err: fmt.Errorf("invalid testssl JSON: %w", err), recoverable: false,
		}
	}
	if len(records) == 0 {
		return nil, &endpointScanError{
			err: fmt.Errorf("testssl produced an empty JSON result"), recoverable: false,
		}
	}
	fatalResult := testsslFatalResult(records)
	if runErr != nil {
		// testssl.sh 3.0.x returns the sum of individual check return values.
		// The numeric exit value can therefore collide with its reserved fatal
		// codes. A well-formed report is usable unless testssl also emitted its
		// explicit scanProblem/FATAL record.
		if fatalResult == "" {
			return data, nil
		}
		return data, classifyExecutionError(runErr)
	}
	if fatalResult != "" {
		return data, &endpointScanError{
			err:         fmt.Errorf("testssl reported a fatal scan problem: %s", fatalResult),
			recoverable: true,
		}
	}
	return data, nil
}

func testsslFatalResult(records []json.RawMessage) string {
	for _, raw := range records {
		var record struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Finding  string `json:"finding"`
		}
		if json.Unmarshal(raw, &record) != nil ||
			!strings.EqualFold(record.ID, "scanProblem") ||
			!strings.EqualFold(record.Severity, "FATAL") {
			continue
		}
		if finding := strings.TrimSpace(record.Finding); finding != "" {
			return finding
		}
		return "unspecified fatal scanner error"
	}
	return ""
}

func classifyExecutionError(err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return err
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		// 246 is testssl.sh's documented connectivity error. Lower codes are
		// aggregate per-check outcomes. Both describe one endpoint, not a broken
		// scanner installation, and may be tolerated when other endpoints pass.
		recoverable := code == 246 || (code > 0 && code < 242)
		return &endpointScanError{err: err, recoverable: recoverable}
	}
	return &endpointScanError{err: err, recoverable: false}
}

// mergeJSONArrays concatenates the elements of several testssl.sh JSON arrays
// into one array so the ingest side sees a single result for the stage. Inputs
// have already been validated by scanOne. Returns nil when nothing merged.
func mergeJSONArrays(parts [][]byte) []byte {
	var all []json.RawMessage
	for _, p := range parts {
		var arr []json.RawMessage
		if json.Unmarshal(p, &arr) == nil {
			all = append(all, arr...)
		}
	}
	if len(all) == 0 {
		return nil
	}
	out, _ := json.Marshal(all)
	return out
}
