// Package nuclei adapts the Nuclei scanner for VulnaScout's vulnerability stage.
//
// Only allowlisted, typed arguments are passed. The safe template policy
// excludes intrusive/DoS/fuzzing templates and limits severities, matching the
// non-destructive assessment mode (build plan Section 12.4).
package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/discovery"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/processutil"
)

const (
	defaultBinary = "nuclei"
	// templatesEnv points nuclei at a bundled templates directory. The scanner
	// image sets it so offline, out-of-the-box vulnerability scans have templates
	// to match against (without it, and with update checks disabled, nuclei loads
	// zero templates and every scan finds nothing).
	templatesEnv = "VULNA_NUCLEI_TEMPLATES"
)

// Excluded template tags for the safe policy: anything intrusive or destructive.
var excludedTags = []string{"dos", "intrusive", "fuzzing", "fuzz", "brute-force"}

// safeSeverities are the severities the safe policy reports.
var safeSeverities = []string{"low", "medium", "high", "critical"}

// BuildArgs builds allowlisted nuclei arguments: read targets from targetFile,
// write JSONL to outPath, applying the safe template policy. When templatesDir is
// non-empty it is passed via -templates so nuclei loads the bundled template set
// instead of relying on an (update-disabled, possibly empty) default directory.
func BuildArgs(outPath, targetFile, templatesDir string, severities []string) []string {
	args := []string{
		"-list", targetFile,
		"-jsonl",
		"-output", outPath,
		// Not -silent: we need nuclei's stderr (the "Templates loaded" line and
		// -stats-json snapshots) to tell a genuinely-clean scan from a broken one
		// where templates failed to load or every request errored. Findings still
		// go to -output, so this doesn't change what we ingest.
		"-stats-json",
		"-no-color",
		"-disable-update-check",
		"-exclude-tags", strings.Join(excludedTags, ","),
	}
	if templatesDir != "" {
		args = append(args, "-templates", templatesDir)
	}
	if len(severities) > 0 {
		args = append(args, "-severity", strings.Join(severities, ","))
	}
	return args
}

// Worker runs Nuclei scans. It satisfies scanners.Scanner.
type Worker struct {
	Binary string
	// Timeout is an optional per-invocation override. Zero inherits the signed,
	// whole-job deadline installed by the agent.
	Timeout      time.Duration
	Severities   []string
	TemplatesDir string
}

// NewWorker returns a Worker with the safe policy. The templates directory is
// taken from VULNA_NUCLEI_TEMPLATES (set by the scanner image); when unset,
// nuclei uses its own default template location.
func NewWorker() *Worker {
	return &Worker{
		Binary:       defaultBinary,
		Severities:   safeSeverities,
		TemplatesDir: os.Getenv(templatesEnv),
	}
}

func (w *Worker) Stage() string { return "vulnerability" }
func (w *Worker) Name() string  { return "nuclei" }

// TargetsFor turns discovered endpoints into nuclei targets: every live host as
// a bare IP (so network and default-port templates run against hosts that are
// actually up), plus an explicit http(s):// URL for each HTTP service so nuclei
// checks web apps on non-standard ports it would otherwise never probe. The
// executor uses this instead of re-handing nuclei the raw address range.
func (w *Worker) TargetsFor(endpoints []discovery.Endpoint) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, e := range endpoints {
		add(e.IP)
		if e.HTTP && e.Transport == "tcp" {
			add(e.URL())
		}
	}
	return out
}

// validateNucleiTarget accepts a bare IP, a CIDR, or an http(s):// URL whose host
// is a literal IP (the service-aware form). Hostnames and flag-like values are
// rejected — an argument-injection and scope defense, since only addresses that
// passed discovery's own validation should ever reach here.
func validateNucleiTarget(t string) error {
	if t == "" || strings.HasPrefix(t, "-") {
		return fmt.Errorf("invalid nuclei target %q", t)
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(t); err == nil {
		return nil
	}
	if u, err := url.Parse(t); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			return nil
		}
	}
	return fmt.Errorf("nuclei target %q is not an IP, CIDR, or http(s) URL to a literal IP", t)
}

func (w *Worker) binary() string {
	if w.Binary != "" {
		return w.Binary
	}
	return defaultBinary
}

func (w *Worker) runContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if w.Timeout > 0 {
		return context.WithTimeout(ctx, w.Timeout)
	}
	return context.WithCancel(ctx)
}

// Run scans the job's targets with nuclei and returns the raw JSONL. Empty
// output (no findings) is a valid result, not an error.
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	for _, t := range job.Targets {
		if err := validateNucleiTarget(t); err != nil {
			return nil, err
		}
	}

	dir, err := os.MkdirTemp("", "vulnascout-nuclei-*")
	if err != nil {
		return nil, fmt.Errorf("create temp workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	targetPath := filepath.Join(dir, "targets.txt")
	targetFile, err := os.Create(targetPath)
	if err != nil {
		return nil, fmt.Errorf("create target file: %w", err)
	}
	for _, t := range job.Targets {
		if _, err := targetFile.WriteString(t + "\n"); err != nil {
			_ = targetFile.Close()
			return nil, err
		}
	}
	_ = targetFile.Close()

	outPath := filepath.Join(dir, "nuclei.jsonl")

	args := BuildArgs(outPath, targetPath, w.TemplatesDir, w.Severities)
	// The agent's parent context carries the signed authorization expiry and the
	// whole-job max duration. Do not reset either limit for every target chunk.
	runCtx, cancel := w.runContext(ctx)
	defer cancel()
	cmd := processutil.ScannerCommandContext(runCtx, dir, w.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data, _ := os.ReadFile(outPath)
	if len(data) == 0 {
		data = nil
	}
	if runCtx.Err() != nil {
		return data, runCtx.Err()
	}
	// A non-zero exit (e.g. the binary is missing) is a real failure; nuclei
	// exits 0 when it simply finds nothing.
	if runErr != nil {
		return data, fmt.Errorf("nuclei failed: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	// A zero exit with empty output can mean "clean" OR "nothing was actually
	// scanned" (templates failed to load, every request errored). Those are not
	// the same, and reporting the latter as a clean pass hides false negatives —
	// so fail loudly instead of silently accepting an untrustworthy result.
	if reason := scanIntegrityFailure(stderr.Bytes()); reason != "" {
		return nil, fmt.Errorf("nuclei result is not trustworthy: %s", reason)
	}
	// Empty output is valid (no findings matched).
	return data, nil
}

var templatesLoadedRE = regexp.MustCompile(`Templates loaded for current scan:\s*(\d+)`)

// nucleiStats mirrors the -stats-json snapshot nuclei writes to stderr. Nuclei
// encodes the counts as strings (e.g. "requests":"350").
type nucleiStats struct {
	Requests string `json:"requests"`
	Errors   string `json:"errors"`
}

// scanIntegrityFailure inspects nuclei's stderr and returns a non-empty reason
// when the run cannot be trusted as a clean scan: zero templates loaded, zero
// requests sent, or every request errored. An empty string means the run looks
// genuine (including a real "no findings" result). It is conservative — anything
// it can't positively identify as broken is treated as fine, so it never turns a
// good scan into a failure.
func scanIntegrityFailure(stderr []byte) string {
	// Printed at scan start regardless of run length; the clearest signal that the
	// bundled template set failed to load (see the templatesEnv note above).
	if m := templatesLoadedRE.FindSubmatch(stderr); m != nil {
		if n, err := strconv.Atoi(string(m[1])); err == nil && n == 0 {
			return "nuclei loaded 0 templates (the bundled template set failed to load)"
		}
	}
	// The most recent -stats-json snapshot: catches runs that reached hosts but
	// where nothing actually completed.
	if s, ok := lastStats(stderr); ok {
		req, _ := strconv.Atoi(s.Requests)
		errs, _ := strconv.Atoi(s.Errors)
		if req == 0 {
			return "nuclei sent 0 requests (nothing was actually scanned)"
		}
		if errs >= req {
			return fmt.Sprintf("all %d nuclei request(s) errored (result is inconclusive)", req)
		}
	}
	return ""
}

// lastStats returns the most recent -stats-json snapshot on stderr, or ok=false
// when none was emitted (e.g. a scan too short for the stats interval), so the
// caller falls back safely rather than misjudging the run.
func lastStats(stderr []byte) (nucleiStats, bool) {
	var latest nucleiStats
	found := false
	for _, line := range bytes.Split(stderr, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' || !bytes.Contains(line, []byte(`"requests"`)) {
			continue
		}
		var s nucleiStats
		if json.Unmarshal(line, &s) == nil && s.Requests != "" {
			latest = s
			found = true
		}
	}
	return latest, found
}
