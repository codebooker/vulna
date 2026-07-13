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
	"regexp"
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

// portSpecRE bounds an nmap -p spec to digits, commas and ranges, so a port set
// can never be mistaken for an nmap flag (argument-injection defense).
var portSpecRE = regexp.MustCompile(`^[0-9][0-9,\-]*$`)

// durationRE bounds an nmap time value (e.g. --host-timeout) to a number with an
// nmap unit suffix, so it can never be mistaken for a flag (argument-injection).
var durationRE = regexp.MustCompile(`^[0-9]+(ms|s|m|h)$`)

// ImportantPorts is the default port set: the whole well-known range (1-1024)
// plus a curated list of high-value service ports that nmap's frequency-based
// --top-ports MISSES — databases, caches, message queues, admin panels,
// alt-HTTP, remote access, and orchestration APIs. Frequency ranking drops these
// because they are statistically rare on the public internet (e.g. Redis 6379
// ranks well below the top-1,000 cutoff), yet they are exactly the services a
// security scan must not miss. Deterministic, so a scan never silently skips a
// known service port.
const ImportantPorts = "1-1024,1099,1433,1434,1521,1723,2049,2082,2083,2181," +
	"2375,2376,2483,2484,3000,3128,3268,3306,3389,3690,4369,4444,4505,4506,4567," +
	"4786,5000,5001,5044,5432,5555,5601,5672,5900-5910,5984,5985,5986,6000,6379," +
	"6443,6666,7000,7001,7077,7199,7473,7474,7687,8000-8010,8020,8042,8080-8091," +
	"8161,8180,8443,8500,8530,8531,8686,8888,9000,9001,9042,9060,9090,9092,9160," +
	"9200,9300,9418,9443,9999,10000,10250,10255,11211,15672,27017,27018,27019," +
	"28017,50000,50070"

// Profile is a curated, non-intrusive discovery configuration.
type Profile struct {
	Ports            string // explicit nmap -p spec; overrides TopPorts when set
	TopPorts         int    // number of top ports to scan (1..65535); used if Ports == ""
	Timing           int    // nmap -T level, clamped to 0..4
	MaxRate          int    // --max-rate packets/sec ceiling (0 = unset)
	MinRate          int    // --min-rate packets/sec floor (0 = unset); clamped to <= MaxRate
	MaxRetries       int    // --max-retries probe retransmissions (0 = unset / nmap default)
	HostTimeout      string // --host-timeout, e.g. "15m" ("" = unset)
	ServiceDetection bool   // -sV
}

// SafeDiscoveryProfile returns the default discovery profile: the curated
// important-ports set (see ImportantPorts) with service detection, over a
// non-privileged TCP connect scan.
//
// It stays deliberately gentle on the network (the packet rate is ceiling-capped
// by the signed policy) but avoids crawling: a --min-rate floor keeps the scan
// from idling on unresponsive hosts (see Worker.Run), retries are trimmed so dead
// addresses aren't retried to death, and a per-host timeout stops one black-hole
// host from starving the run.
func SafeDiscoveryProfile() Profile {
	return Profile{
		Ports:            ImportantPorts,
		Timing:           3,
		MaxRetries:       2,
		HostTimeout:      "15m",
		ServiceDetection: true,
	}
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
	// -sT: TCP connect (no raw sockets/root). -n: no DNS. -Pn: skip host discovery
	// and assess the target directly. Targets are already scope-approved by the
	// operator, so the scan must not silently skip a host that doesn't answer a
	// ping — unprivileged host discovery is unreliable (ICMP is commonly filtered),
	// which would drop live, in-scope hosts from the assessment.
	args := []string{"-sT", "-n", "-Pn"}
	if profile.ServiceDetection {
		args = append(args, "-sV")
	}
	args = append(args, "-T"+strconv.Itoa(clamp(profile.Timing, 0, 4)))
	if profile.Ports != "" {
		if !portSpecRE.MatchString(profile.Ports) {
			return nil, fmt.Errorf("invalid port spec %q", profile.Ports)
		}
		args = append(args, "-p", profile.Ports)
	} else {
		top := clamp(profile.TopPorts, 1, maxTopPorts)
		args = append(args, "--top-ports", strconv.Itoa(top))
	}
	if profile.MaxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(profile.MaxRate))
	}
	// A rate floor keeps nmap from throttling itself to a crawl on unresponsive
	// hosts, but never above the ceiling, so the traffic stays bounded.
	minRate := profile.MinRate
	if profile.MaxRate > 0 && minRate > profile.MaxRate {
		minRate = profile.MaxRate
	}
	if minRate > 0 {
		args = append(args, "--min-rate", strconv.Itoa(minRate))
	}
	if profile.MaxRetries > 0 {
		args = append(args, "--max-retries", strconv.Itoa(profile.MaxRetries))
	}
	if profile.HostTimeout != "" {
		if !durationRE.MatchString(profile.HostTimeout) {
			return nil, fmt.Errorf("invalid host-timeout %q", profile.HostTimeout)
		}
		args = append(args, "--host-timeout", profile.HostTimeout)
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
		// Hold a floor at half the operator-approved ceiling so the scan never
		// drops to a crawl on dead space, while the ceiling still bounds the load.
		profile.MinRate = profile.MaxRate / 2
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
