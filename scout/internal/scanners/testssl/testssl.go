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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/codebooker/vulna/scout/internal/discovery"
	"github.com/codebooker/vulna/scout/internal/policy"
)

const (
	defaultBinary  = "testssl.sh"
	defaultTimeout = 15 * time.Minute
	defaultPort    = 443
)

// BuildArgs builds allowlisted testssl.sh arguments for one host:port, writing
// JSON to outPath.
func BuildArgs(outPath, hostPort string) []string {
	return []string{
		"--quiet",
		"--color", "0",
		"--warnings", "batch",
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
		if !e.TLS || e.Transport != "tcp" {
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
// merged JSON. Each discovered host:port (or bare IP on the configured port) is
// scanned in turn — not just the first — so a scan of several hosts, or of
// service-aware TLS endpoints, no longer silently checks only one of them. When
// there are no single-host endpoints (e.g. only CIDR targets), it returns no
// output. A host with no reachable TLS is skipped, but the testssl.sh binary
// being unavailable fails the stage loudly rather than reporting a clean scan.
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	endpoints := w.endpoints(job.Targets)
	if len(endpoints) == 0 {
		return nil, nil
	}

	var parts [][]byte
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		data, err := w.scanOne(ctx, ep)
		if err != nil {
			// The binary not being found means TLS scanning is broken, not that a
			// host lacks TLS — surface it instead of hiding it as an empty result.
			if errors.Is(err, exec.ErrNotFound) {
				return nil, fmt.Errorf("testssl.sh unavailable: %w", err)
			}
			// Otherwise testssl ran but this endpoint had no scannable TLS (non-zero
			// exit, no output). That is a normal per-host outcome — skip it and keep
			// scanning the remaining endpoints.
			continue
		}
		if len(data) > 0 {
			parts = append(parts, data)
		}
	}
	return mergeJSONArrays(parts), nil
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
	cmd := exec.CommandContext(runCtx, w.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data, _ := os.ReadFile(outPath)
	if len(data) == 0 {
		// No JSON produced: propagate the run error (which may be exec.ErrNotFound)
		// so Run can tell a missing binary from a host that simply has no TLS.
		if runErr != nil {
			return nil, runErr
		}
		return nil, nil
	}
	return data, nil
}

// mergeJSONArrays concatenates the elements of several testssl.sh JSON arrays
// into one array so the ingest side sees a single result for the stage. Parts
// that don't parse as a JSON array are skipped. Returns nil when nothing merged.
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
