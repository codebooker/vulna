// Package installer renders preflight results and install plans and gathers the
// small set of interactive choices. It contains no side effects beyond reading
// from the provided input and writing to the provided output.
package installer

import (
	"fmt"
	"io"

	"github.com/codebooker/vulna/cli/internal/config"
	"github.com/codebooker/vulna/cli/internal/deploy"
	"github.com/codebooker/vulna/cli/internal/preflight"
)

// PrintPreflight writes a human-readable preflight report.
func PrintPreflight(w io.Writer, results []preflight.Result) {
	fmt.Fprintln(w, "Preflight checks:")
	for _, r := range results {
		mark := map[preflight.Status]string{
			preflight.OK: "ok  ", preflight.Warn: "WARN", preflight.Fail: "FAIL",
		}[r.Status]
		fmt.Fprintf(w, "  [%s] %-18s %s\n", mark, r.Name, r.Detail)
		if r.Status != preflight.OK {
			if r.Problem != "" {
				fmt.Fprintf(w, "         problem:   %s\n", r.Problem)
			}
			if r.Impact != "" {
				fmt.Fprintf(w, "         impact:    %s\n", r.Impact)
			}
			if r.NextStep != "" {
				fmt.Fprintf(w, "         next step: %s\n", r.NextStep)
			}
		}
	}
	okN, warnN, failN := preflight.Counts(results)
	fmt.Fprintf(w, "Summary: %d ok, %d warning(s), %d failure(s)\n", okN, warnN, failN)
}

// PrintPlan writes the changes an install would make (used by --dry-run).
func PrintPlan(w io.Writer, plan deploy.Plan, o config.Options) {
	fmt.Fprintf(
		w,
		"Install plan (profile: %s, access mode: %s, URL: %s):\n",
		o.DeploymentProfile,
		o.AccessMode,
		o.Domain(),
	)
	fmt.Fprintln(w, "  Filesystem changes:")
	for _, a := range plan.Actions {
		secret := ""
		if a.Secret {
			secret = " [secret, 0600]"
		}
		note := ""
		if a.Note != "" {
			note = " — " + a.Note
		}
		fmt.Fprintf(w, "    %-6s %s (mode %#o)%s%s\n", a.Kind, a.Path, a.Mode, secret, note)
	}
	fmt.Fprintf(w, "  Services started: %v\n", plan.Services)
	fmt.Fprintf(w, "  Published ports:  %v\n", plan.Ports)
	fmt.Fprintln(w, "  Capabilities:")
	for _, c := range plan.Capabilities {
		fmt.Fprintf(w, "    - %s\n", c)
	}
	fmt.Fprintln(w, "  No secrets are printed. No data volumes are removed.")
}
