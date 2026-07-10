// Package cli implements command dispatch for the vulnascout binary.
//
// Phase 0 provides `version` and `self-test`. Later phases add `enroll`,
// `status`, `diagnostics`, `policy`, `scan stop`, `update`, `logs`, and `reset`.
package cli

import (
	"fmt"
	"io"

	"github.com/codebooker/vulna/scout/internal/buildinfo"
	"github.com/codebooker/vulna/scout/internal/selftest"
)

const usage = `vulnascout — Vulna remote assessment appliance (VulnaScout)

Usage:
  vulnascout <command>

Commands:
  version      Print version and build information
  self-test    Run local, non-destructive diagnostics
  help         Show this help message

Authorized use only. See SECURITY.md and docs/authorized-use.md.
`

// Execute runs the CLI with the given arguments (excluding the program name)
// and returns a process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch args[0] {
	case "version", "--version", "-v":
		return runVersion(stdout)
	case "self-test", "selftest":
		return runSelfTest(stdout)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %q\n\n", args[0])
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func runVersion(w io.Writer) int {
	fmt.Fprintf(w, "vulnascout %s\n", buildinfo.Version)
	fmt.Fprintf(w, "  commit: %s\n", buildinfo.Commit)
	fmt.Fprintf(w, "  built:  %s\n", buildinfo.Date)
	return 0
}

func runSelfTest(w io.Writer) int {
	checks := selftest.Run()
	for _, c := range checks {
		status := "ok"
		if !c.OK {
			if c.Required {
				status = "FAIL"
			} else {
				status = "absent"
			}
		}
		fmt.Fprintf(w, "[%-6s] %-18s %s\n", status, c.Name, c.Detail)
	}
	if selftest.Passed(checks) {
		fmt.Fprintln(w, "\nself-test: PASS")
		return 0
	}
	fmt.Fprintln(w, "\nself-test: FAIL")
	return 1
}
