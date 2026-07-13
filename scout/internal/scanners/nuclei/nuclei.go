// Package nuclei adapts the Nuclei scanner for VulnaScout's vulnerability stage.
//
// Only allowlisted, typed arguments are passed. The safe template policy
// excludes intrusive/DoS/fuzzing templates and limits severities, matching the
// non-destructive assessment mode (build plan Section 12.4).
package nuclei

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/scanners"
)

const (
	defaultBinary  = "nuclei"
	defaultTimeout = 30 * time.Minute
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
		"-silent",
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
	Binary       string
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
		Timeout:      defaultTimeout,
		Severities:   safeSeverities,
		TemplatesDir: os.Getenv(templatesEnv),
	}
}

func (w *Worker) Stage() string { return "vulnerability" }
func (w *Worker) Name() string  { return "nuclei" }

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

// Run scans the job's targets with nuclei and returns the raw JSONL. Empty
// output (no findings) is a valid result, not an error.
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	for _, t := range job.Targets {
		if err := scanners.ValidateTarget(t); err != nil {
			return nil, err
		}
	}

	targetFile, err := os.CreateTemp("", "vulnascout-nuclei-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create target file: %w", err)
	}
	targetPath := targetFile.Name()
	defer func() { _ = os.Remove(targetPath) }()
	for _, t := range job.Targets {
		if _, err := targetFile.WriteString(t + "\n"); err != nil {
			_ = targetFile.Close()
			return nil, err
		}
	}
	_ = targetFile.Close()

	outFile, err := os.CreateTemp("", "vulnascout-nuclei-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer func() { _ = os.Remove(outPath) }()

	args := BuildArgs(outPath, targetPath, w.TemplatesDir, w.Severities)
	// Bound the run by the policy-approved duration when present, so a legitimate
	// vulnerability stage over many discovered hosts isn't killed by the fixed
	// fallback timeout (nuclei is SIGKILLed at the deadline, failing the job).
	timeout := w.timeout()
	if secs := job.Limits.MaxDurationSeconds; secs > 0 {
		timeout = time.Duration(secs) * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, w.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// A non-zero exit (e.g. the binary is missing) is a real failure; nuclei
	// exits 0 when it simply finds nothing.
	if runErr != nil {
		return nil, fmt.Errorf("nuclei failed: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	data, _ := os.ReadFile(outPath)
	// Empty output is valid (no findings matched).
	return data, nil
}
