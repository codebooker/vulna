// Package nmap adapts the Nmap scanner for VulnaScout's discovery stage.
//
// Only allowlisted, typed arguments are ever passed to nmap — never a free-form
// command string from the orchestrator (build plan Sections 4.4 and 12.3). The
// safe discovery profile uses a TCP connect scan (`-sT`), which needs no raw
// sockets or root, matching the hardened, unprivileged agent.
package nmap

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
)

const (
	defaultBinary  = "nmap"
	defaultTimeout = 30 * time.Minute
	maxTopPorts    = 65535
)

// Profile is a curated, non-intrusive discovery configuration.
type Profile struct {
	TopPorts         int  // number of top ports to scan (1..65535)
	Timing           int  // nmap -T level, clamped to 0..4
	MaxRate          int  // --max-rate packets/sec (0 = unset)
	ServiceDetection bool // -sV
}

// SafeDiscoveryProfile returns the default Phase 4 discovery profile.
func SafeDiscoveryProfile() Profile {
	return Profile{TopPorts: 100, Timing: 3, ServiceDetection: true}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// validateTarget ensures a target is a plain IP or CIDR and cannot be mistaken
// for an nmap flag (argument-injection defense).
func validateTarget(target string) error {
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target %q must not start with '-'", target)
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(target); err == nil {
		return nil
	}
	return fmt.Errorf("target %q is not a valid IP or CIDR", target)
}

// BuildArgs builds the nmap argument list for a profile, writing XML to outPath.
// Targets must be plain IPs/CIDRs; anything else is rejected.
func BuildArgs(profile Profile, outPath string, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	args := []string{"-sT", "-n"} // TCP connect, no DNS resolution
	if profile.ServiceDetection {
		args = append(args, "-sV")
	}
	args = append(args, "-T"+strconv.Itoa(clamp(profile.Timing, 0, 4)))
	top := clamp(profile.TopPorts, 1, maxTopPorts)
	args = append(args, "--top-ports", strconv.Itoa(top))
	if profile.MaxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(profile.MaxRate))
	}
	args = append(args, "-oX", outPath)
	for _, t := range targets {
		if err := validateTarget(t); err != nil {
			return nil, err
		}
		args = append(args, t)
	}
	return args, nil
}

// Worker runs Nmap discovery scans. It satisfies executor.JobRunner.
type Worker struct {
	Binary  string
	Profile Profile
	Timeout time.Duration
}

// NewWorker returns a Worker with the safe discovery profile.
func NewWorker() *Worker {
	return &Worker{Binary: defaultBinary, Profile: SafeDiscoveryProfile(), Timeout: defaultTimeout}
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

// Stage is the workflow stage this scanner implements.
func (w *Worker) Stage() string { return "discovery" }

// Name is the plugin name matched against the job workflow.
func (w *Worker) Name() string { return "nmap" }

// Run scans the job's targets with nmap and returns the raw XML. It honors
// context cancellation (killing the nmap process) and applies the job's
// packet-rate limit. Targets are assumed already scope-validated by the agent;
// they are additionally checked here for argument safety.
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	outFile, err := os.CreateTemp("", "vulnascout-nmap-*.xml")
	if err != nil {
		return nil, fmt.Errorf("create temp output: %w", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer func() { _ = os.Remove(outPath) }()

	profile := w.Profile
	if job.Limits.MaxPacketsPerSecond > 0 {
		profile.MaxRate = job.Limits.MaxPacketsPerSecond
	}
	args, err := BuildArgs(profile, outPath, job.Targets)
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, w.timeout())
	defer cancel()
	cmd := exec.CommandContext(runCtx, w.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	xml, _ := os.ReadFile(outPath)
	if len(xml) == 0 {
		return nil, fmt.Errorf(
			"nmap produced no output: %v: %s", runErr, strings.TrimSpace(stderr.String()),
		)
	}
	return xml, nil
}
