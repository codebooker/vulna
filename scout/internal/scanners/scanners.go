// Package scanners defines the scanner-plugin interface and a workflow runner
// that dispatches a job's workflow stages to the matching scanner adapters.
package scanners

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/policy"
)

// ValidateTarget ensures a target is a plain IP or CIDR and cannot be mistaken
// for a command flag — an argument-injection defense shared by adapters.
func ValidateTarget(target string) error {
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

// Scanner is a plugin that runs one stage of a workflow against a job's targets
// and returns raw output to upload. Implementations must honor context
// cancellation (the kill switch) and never accept free-form arguments.
type Scanner interface {
	// Stage is the workflow stage the scanner implements (e.g. "discovery").
	Stage() string
	// Name is the plugin name matched against the job workflow (e.g. "nmap").
	Name() string
	// Run executes the scan and returns its raw output.
	Run(ctx context.Context, job *policy.Job) ([]byte, error)
}

// Workflow runs a job's workflow by dispatching each stage's plugin to the
// registered scanner. It satisfies executor.JobRunner.
type Workflow struct {
	byPlugin map[string]Scanner
}

// NewWorkflow registers the given scanners by plugin name.
func NewWorkflow(list ...Scanner) *Workflow {
	byPlugin := make(map[string]Scanner, len(list))
	for _, s := range list {
		byPlugin[s.Name()] = s
	}
	return &Workflow{byPlugin: byPlugin}
}

// Run executes each workflow stage whose plugin is registered, collecting each
// stage's output. Unknown/unavailable plugins are skipped; a stage that errors
// is skipped (continue-with-warning). Cancellation stops promptly.
func (w *Workflow) Run(ctx context.Context, job *policy.Job) (executor.Result, error) {
	res := executor.Result{JobID: job.JobID, StagesTotal: len(job.Workflow)}
	for _, stage := range job.Workflow {
		plugin, _ := stage["plugin"].(string)
		scanner, ok := w.byPlugin[plugin]
		if !ok {
			continue
		}
		if ctx.Err() != nil {
			res.Cancelled = true
			return res, ctx.Err()
		}
		raw, err := scanner.Run(ctx, job)
		if ctx.Err() != nil {
			res.Cancelled = true
			return res, ctx.Err()
		}
		if err != nil {
			continue // on_failure: continue with warning
		}
		res.Outputs = append(res.Outputs, executor.StageOutput{
			Stage: scanner.Stage(), Scanner: scanner.Name(), Raw: raw,
		})
		res.StagesRun++
	}
	return res, nil
}
