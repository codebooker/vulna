// Package testssl adapts testssl.sh for VulnaScout's TLS stage.
//
// testssl.sh scans one host:port at a time. Only allowlisted, typed arguments
// are passed, with conservative, non-interactive settings (build plan
// Section 12.6).
package testssl

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/scanners"
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

// firstSingleHost returns the first target that is a single IP address (not a
// CIDR); testssl.sh cannot scan a range.
func firstSingleHost(targets []string) string {
	for _, t := range targets {
		if _, err := netip.ParseAddr(t); err == nil {
			return t
		}
	}
	return ""
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

// Run scans the first single-host target's TLS on the configured port and
// returns the raw JSON. If no single-host target is present, it returns no
// output (nothing to scan).
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	target := firstSingleHost(job.Targets)
	if target == "" {
		return nil, nil
	}
	if err := scanners.ValidateTarget(target); err != nil {
		return nil, err
	}

	// testssl.sh will not overwrite an existing --jsonfile, so hand it a fresh
	// path inside a temp dir rather than a pre-created file.
	dir, err := os.MkdirTemp("", "vulnascout-testssl-*")
	if err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	outPath := filepath.Join(dir, "testssl.json")

	hostPort := net.JoinHostPort(target, strconv.Itoa(w.port()))
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
		return nil, fmt.Errorf(
			"testssl produced no output: %v: %s", runErr, strings.TrimSpace(stderr.String()),
		)
	}
	return data, nil
}
